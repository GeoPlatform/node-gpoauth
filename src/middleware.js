const jwt = require('jsonwebtoken');
const color = require('./consoleColors.js')
const tokenHandler = require('./tokenHandler.js')



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

  /**
   * Grant access with given token.
   *
   *
   * @param {JWT} accessToken
   * @param {Request} req
   * @param {Response} res
   * @param {function} next
   */
  function grantAccess(req, res, next){
    const accessToken = tokenHandler.getAccessToken()
    const JWT = tokenHandler.getJWT()

    req.accessToken = accessToken
    req.jwt = JWT
    LOGGER.logRequest('Access Granted', accessToken, req)

    if(emitter.listenerCount('accessGranted') > 0){
      emitter.emit('accessGranted', req, res, next);
    } else {
      next();
    }
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

    const accessToken = tokenHandler.getAccessToken(req);

    if(!tokenHandler.getSignature()){
      // Git the signature then try again
      AUTH.fetchJWTSignature()
        .then(sig => {
          tokenHandler.setSignature(sig);
          verifyJWT(req, res, next)/* try again */
        })
        .catch(err => {
          LOGGER.logRequest('Unauthorized Request', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        })

    // Do the actual validtion here
    } else {
      try {
        const jwt = tokenHandler.validateAccessToken(accessToken)

        // Force refresh if withing REFRESH_DEBOUNCE buffer
        const now = (new Date()).getTime();
        if(needsRefreshed(now, jwt.exp * 1000, CONFIG.PRE_REFRESH_BUFFER))
          throw new jwt.TokenExpiredError('Token is past PRE_REFRESH_BUFFER limit', now - CONFIG.PRE_REFRESH_BUFFER);

        // Pass them through
        grantAccess(req, res, next)

      } catch(err) {
        if (err instanceof jwt.TokenExpiredError) {
          // DT-2048: allow refreshToken to linger for delayed (CONFIG.REFRESH_LINGER))
          const NOW = (new Date()).getTime() / 1000
          const MAX_ALLOWED = (new Date(accessToken.exp + CONFIG.REFRESH_LINGER)).getTime() / 1000
          if(NOW >= MAX_ALLOWED){
            // Allow them through because time left on linger
            grantAccess(req, res, next)

          } else {
            // Past MAX_ALLOWS : token is actually expired
            LOGGER.logRequest(`Expired token used: ${err}`, accessToken, req)
            refreshDebounce(accessToken, req, res, next);
          }

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
   * Side effects:
   *  - sets the access token in cookie on successful refresh
   *
   * @method refreshAccessToken
   * @see returned function for params list
   */
  const refreshDebounce = (function(){
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
    function reProcessReqeustWithNewToken(refreshQueueRecord, newAccessToken, newRefreshToken){
        // Pass back to verifyJWT for processing
        refreshQueueRecord.queue.map(r => {
          // Update request with new token to pass validation (post refresh)
          tokenHandler.setTokens(r.res, newAccessToken, newRefreshToken)

          // Pass back to verify
          verifyJWT(r.req, r.res, r.next)
        })
    }

    /**
     * The actual work of refreshing a token
     *
     * @param {*} refreshQueueRecord
     * @param {*} req
     * @param {*} res
     * @param {*} next
     */
    async function refreshAccessToken(req){
      const expiredAccessToken = tokenHandler.getAccessToken(req)
      const oldRefreshToken = tokenHandler.getRefreshToken(req)

      LOGGER.debug(`-- Attempting AccessToken Refresh - Token: ${LOGGER.tokenDemo(expiredAccessToken)} --`)
      return AUTH.requestTokenFromRefreshToken(oldRefreshToken)
            .then(refResp => {
              LOGGER.debug("=== Refresh Succeeded ===")
              LOGGER.debug("======= New Token =======")
              LOGGER.debug('|| Access:  ' + LOGGER.tokenDemo(refResp.access_token))
              LOGGER.debug('|| Refresh: ' + LOGGER.tokenDemo(refResp.refresh_token))
              LOGGER.debug("=========================")

              return {
                access_token: refResp.access_token,
                refresh_token: refResp.refresh_token
              }
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
    return function(expiredAccessToken, req, res, next){
      // Debounce
      let refreshQueueRecord = refreshQueue[expiredAccessToken]
      if(refreshQueueRecord){
        // Debounce the call to fetch refresh token
        clearTimeout(refreshQueueRecord.request)
        refreshQueueRecord.queue.push({ req, res, next });
      } else {
        // Add refreshQueue record if none existing for this oldAccessToken
        refreshQueue[expiredAccessToken] = {
          request: null,
          queue: [{ req, res, next }]
        }
      }

      // Make sure we have the right record (post upsert)
      refreshQueueRecord = refreshQueue[expiredAccessToken]

      // Go ahead an fetch new AccessToken
      // TODO: lift this function at some point....
      refreshQueueRecord.request = setTimeout(() => {
        refreshAccessToken(req)
          .then(tokens => {
            if (tokens.access_token){
              tokenHandler.setTokens(res, tokens.access_token, tokens.refresh_token)
              reProcessReqeustWithNewToken(refreshQueueRecord, tokens.access_token, tokens.refresh_token)

            } else {
              LOGGER.debug(`-- Refresh Failed : no tokens returned from IDP refresh (refresh token had likely expired) --`)
              tokenHandler.clearTokens(res)
              AUTH.sendRefreshErrorEvent(new Error('Failed to refresh token with IDP service.'), req, res, next);
            }

          })
          .catch(err => {
            LOGGER.debug(`${color.FgRed}=== Error on refresh token: ===${color.Reset}`);
            LOGGER.debug(err.message)
            tokenHandler.clearTokens(res)
            AUTH.sendRefreshErrorEvent(err, req, res, next);
          })
      }, CONFIG.REFRESH_DEBOUNCE);
    }
  })();

  // Exposing ======================================
  return { verifyJWT }
}