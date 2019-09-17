const jwt = require('jsonwebtoken');
const tokenCache = require('./tokenCache.js');
const color = require('./consoleColors.js')
const REVOKE_RESPONSE = require('./Constants.json').REVOKE_RESPONSE

/**
 * Get the accessToken from request.
 *
 * @param {Request} req
 */
function getToken(req){
  return (req.headers.authorization || '').replace('Bearer ','');
}

/**
 * node-gpoauth middleware
 *
 * @param {Object} CONFIG - node-gpoauth configuration
 * @param {Express.application} app - Express Appliction
 * @param  {Object} emitter - instanciated Events object
 */
module.exports = function(CONFIG, emitter){
  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);
  const AUTH = require('./oauth.js')(CONFIG, emitter)

  /**
   * Emits an UnauthorizedRequest event or an error if the event does not have
   * a registered handler.
   *
   * @method fireUnauthorizedRequest
   * @param {Error} err
   * @param {Request} req
   * @param {Response} res
   * @param {function} next
   */
  function fireUnauthorizedRequest(err, req, res, next){
    if(emitter.listenerCount('unauthorizedRequest') > 0){
      emitter.emit('unauthorizedRequest', err, req, res, next);

      // Require 'unauthorizedRequest' event handler inside hosting application
    } else {
      const msg = [
        'node-gpoauth error\n',
        'No event handler registered for the "unauthorizedRequest" event.\n',
        'Your data is not secured by gpoauth!\n\n',
        'Please see: ',
        'https://github.com/GeoPlatform/node-gpoauth#unauthorizedrequest-required ',
        'for implementing this event handler.\n'
      ].join('')
      next(LOGGER.formalError(msg)); // Fail if no handler setup
    }
  }

  /**
   * Does the accessToken need to be refrehed.
   *
   * @method needsRefreshed
   * @param {Number} now - Unix time stamp (in seconds)
   * @param {Number} exp - Unix time stamp (in seconds)
   * @param {Number} buffer - number of seconds for pre-refresh
   *
   * @return boolean
   */
  function needsRefreshed(now, exp, buffer){
    return now >= (exp - buffer);
  }


  /**************** Middleware ****************/

  /**
   * Middleware for vaidating a JWT passed in the Authorization Header
   * when requesting a resource.
   *
   * This function conforms to standard Connect middleware specs.
   *
   */
  function verifyJWT(req, res, next) {
    // Pass them through on endpoints setup by node-gpoauth
    if(req.originalUrl.match(/login/)
      || req.originalUrl.match(/revoke/)
      || req.originalUrl.match(/authtoken/)
      || req.originalUrl.match(/auth\/loading/)
      // Omit "/checktoken" endpoint so that it will initiate a refresh
    ){
      next();
      return // end execution
    }

    const accessToken = getToken(req);

    if(!tokenCache.getSignature()){
      // Git the signature then try again
      AUTH.fetchJWTSignature()
        .then(sig => {
          tokenCache.setSignature(sig);
          verifyJWT(req, res, next)/* try again */
        })
        .catch(err => {
          LOGGER.logRequest('Unauthorized Request', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        })

    // Do the actual validtion here
    } else {
      try {
        const decoded = jwt.verify(accessToken, tokenCache.getSignature());

        // Force refresh if withing REFRESH_DEBOUNCE buffer
        const now = (new Date()).getTime();
        if(needsRefreshed(now, decoded.exp * 1000, CONFIG.PRE_REFRESH_BUFFER))
          throw new jwt.TokenExpiredError('Token is past PRE_REFRESH_BUFFER limit', now - CONFIG.PRE_REFRESH_BUFFER);

        req.jwt = decoded
        req.accessToken = accessToken
          LOGGER.logRequest('Access Granted', accessToken, req)

        if(emitter.listenerCount('accessGranted') > 0){
          emitter.emit('accessGranted', req, res, next);
        } else {
          next();
        }

      } catch(err) {
        if (err instanceof jwt.TokenExpiredError) {
          LOGGER.logRequest(`Expired token used: ${err}`, accessToken, req)
          refreshAccessToken(accessToken, req, res, next);

        } else {
          // Call the listener 'unauthorizedRequest' handler if registered
          LOGGER.logRequest('Unauthorized Request', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        }
      }
    }
  }


  /**
   * Takes an expired AccessToken and exchanges it for a new one (via a
   * refreshToken). This funtion will debounce requests with the same AccessToken
   * and resolve all of them together (once the new token is aquired).
   *
   * External Deps:
   *  - tokenCache: a TokenCache instance
   *
   * Side effects:
   *  - Adds a new AccessToken / RefreshToken pair to tokenCache
   *  - Removes expired AccessToken / RefreshToken pair from tokenCache
   *  - sets the Authorization header on the response object on successful refresh
   *
   * @method refreshAccessToken
   * @see returned function for params list
   */
  const refreshAccessToken = (function(){
    // encloing scope: private variables for returned function

   /*
    * Object for queuing refresh request (debounce). This keeps track of all
    * pending requests for a new refresh token along with all the requests
    * to the server awaiting an authentication decision.
    *
    * Schema:
    *  {
    *    accessToken: {
    *      request: ,   // id of function call to refresh token
    *      queue: [{    // req, res, next to pass to calls awaiting middleware
    *        req: req   // express request object
    *        res: res   // express response object
    *        next: next // express next function
    *      }]
    *    },
    *    ...
    *  }
    */
    let refreshQueue = {}

    /**
     * Run reqeusts back through the validation process with new token.
     *
     * @param {*} refreshQueueRecord
     * @param {*} newAccessToken
     */
    function reProcessReqeustWithNewToken(refreshQueueRecord, newAccessToken){
        // Pass back to verifyJWT for processing
        refreshQueueRecord.queue.map(r => {
          // Update request with new token to pass validation (post refresh)
          r.req.headers.authorization = `Bearer ${newAccessToken}`;
          // Pass back to verify
          verifyJWT(r.req, r.res, r.next)
        })
    }

    /**
     * The function assigned to refreshAccessToken. This is the callable
     * function.
     *
     * @param {AccessToken} oldAccessToken - expired AccessToken to refresh
     * @param {Request} req - Express request object
     * @param {Response} res - Express response object
     * @param {Middleware next} next - Express middleware next function
     */
    return function(oldAccessToken, req, res, next){
      const oldRefreshToken = tokenCache.getRefreshToken(oldAccessToken)

      if (!!oldRefreshToken) {

        // Token already refrehsed just pass along with new token
        if(tokenCache.hasBeenRefreshed(oldAccessToken)){
          const newest = tokenCache.getLatestToken(oldAccessToken);
          LOGGER.debug(`${color.FgGreen}New AccessToken in cache, passing on request with new AccessToken: ${color.Reset} ${LOGGER.tokenDemo(oldAccessToken)} => ${LOGGER.tokenDemo(newest)}`)
          req.headers.authorization = `Bearer ${newest}`;
          verifyJWT(req, res, next)


        // Token needs to be refreshed
        } else {

          if(refreshQueue[oldAccessToken]){
            // Debounce the call to fetch refresh token
            clearTimeout(refreshQueue[oldAccessToken].request)
            refreshQueue[oldAccessToken].queue.push({ req, res, next });
          } else {
            // Add refreshQueue record if none existing for this oldAccessToken
            refreshQueue[oldAccessToken] = {
              request: null,
              queue: [{ req, res, next }]
            }
          }

          let refreshQueueRecord = refreshQueue[oldAccessToken]

          // Go ahead an fetch new AccessToken
          refreshQueueRecord.request = setTimeout(() => {
            LOGGER.debug(`-- Attempting AccessToken Refresh - Token: ${LOGGER.tokenDemo(oldAccessToken)} --`)
            AUTH.requestTokenFromRefreshToken(oldRefreshToken)
              .then(refResp => {
                const newAccessToken = refResp.access_token;
                const newRefreshToken = refResp.refresh_token;

                if(newAccessToken) {
                  LOGGER.debug("== Refresh Succeeded ==")
                  LOGGER.debug("======= New Token =======")
                  LOGGER.debug('|| Access:  ' + LOGGER.tokenDemo(newAccessToken))
                  LOGGER.debug('|| Refresh: ' + LOGGER.tokenDemo(newRefreshToken))
                  LOGGER.debug("=========================")

                  // Update Cache with new AccessToken
                  tokenCache.setNewAccessToken(oldAccessToken, newAccessToken)
                  LOGGER.debug(`-- Added newAccessToken to old TokenCache --`)

                  // Add new refresh token to the cache
                  tokenCache.add(newAccessToken, newRefreshToken);
                  LOGGER.debug(`TokenCache updated - added: ${LOGGER.tokenDemo(newAccessToken)}`)

                  res.header('Authorization', 'Bearer ' + newAccessToken);
                  LOGGER.debug(`Authorization token sent to browser: '${color.FgBlue}Bearer ${LOGGER.tokenDemo(newAccessToken)}${color.Reset}'`)

                  // DT-2048: allow refreshToken to linger for delayed
                  setTimeout(() => {
                    // Remove old & add new refreshTokens to cache.
                    tokenCache.remove(oldAccessToken);
                    delete refreshQueue[oldAccessToken];
                    LOGGER.debug(`TokenCache updated - removed: ${LOGGER.tokenDemo(oldAccessToken)}`)
                  }, CONFIG.REFRESH_LINGER)

                  reProcessReqeustWithNewToken(refreshQueueRecord, newAccessToken)
                  // // Pass back to verifyJWT for processing
                  // refreshQueueRecord.queue.map(r => {
                  //   // Update request with new token to pass validation (post refresh)
                  //   r.req.headers.authorization = `Bearer ${newAccessToken}`;
                  //   // Pass back to verify
                  //   verifyJWT(r.req, r.res, r.next)
                  // })


                // Refresh failed
                } else {
                  LOGGER.debug(`-- Refresh Failed : no tokens returned from IDP refresh (refresh token had likely expired) --`)
                  tokenCache.remove(oldAccessToken)
                  LOGGER.debug(`TokenCache updated - removed: ${LOGGER.tokenDemo(oldAccessToken)}`)
                  AUTH.sendRefreshErrorEvent(new Error('Failed to refresh token with IDP service.'), req, res, next);
                }

              })
              .catch(err => {
                LOGGER.debug(`${color.FgRed}=== Error on refresh token: ===${color.Reset}`);
                LOGGER.debug(err.message)
                tokenCache.remove(oldAccessToken)
                AUTH.sendRefreshErrorEvent(err, req, res, next);
              })
          }, CONFIG.REFRESH_DEBOUNCE);
        }

      } else {
        const msg = `${color.FgRed}Error on refresh token: No valid refresh token found for accessToken${color.Reset} ${LOGGER.tokenDemo(oldAccessToken)}`
        LOGGER.debug(msg);
        AUTH.sendRefreshErrorEvent(new Error(msg), req, res, next)
      }
    }
  })();

  // Exposing ======================================
  return { verifyJWT }
}