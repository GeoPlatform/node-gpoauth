const JWT = require('jsonwebtoken');
const TokenExpiredError = JWT.TokenExpiredError
const color = require('./consoleColors.js')

/**
 * Store of lingering tokens to keep track of what has already been refrehsed.
 */
let lingeringTokenStore = new Map()

/**
 * node-gpoauth middleware
 *
 * @param {Object} CONFIG - node-gpoauth configuration
 * @param {Express.application} app - Express Appliction
 * @param  {Object} emitter - instanciated Events object
 */
module.exports = function(CONFIG, emitter, tokenHandler){
  const AUTH = require('./oauth.js')(CONFIG, emitter)
  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);

  /**
   * The actual work of refreshing a token
   *
   * @param {*} req
   */
  async function requestRefreshToken(req){
    const expiredAccessToken = tokenHandler.getAccessToken(req)
    const oldRefreshToken = await tokenHandler.getRefreshToken(req)

    if(oldRefreshToken){
      LOGGER.debug(`-- Attempting Token Refresh - Access: ${LOGGER.tokenDemo(expiredAccessToken)} | Refresh : ${LOGGER.tokenDemo(oldRefreshToken)} --`)
      return AUTH.requestTokenFromRefreshToken(oldRefreshToken)
            .then(refResp => {
              if(refResp.access_token && refResp.refresh_token){
                LOGGER.debug("=== Refresh Succeeded ===")
                LOGGER.debug("======= New Token =======")
                LOGGER.debug('|| Access:  ' + LOGGER.tokenDemo(refResp.access_token))
                LOGGER.debug('|| Refresh: ' + LOGGER.tokenDemo(refResp.refresh_token))
                LOGGER.debug("=========================")

                return {
                  access_token: refResp.access_token,
                  refresh_token: refResp.refresh_token
                }
              } else {
                return {}
              }
            })

    } else {
      return {}
    }
  }


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
    const accessToken = tokenHandler.getAccessToken(req)
    const jwt = tokenHandler.getJWT(req)

    req.accessToken = accessToken
    req.jwt = jwt
    LOGGER.logRequest('Access Granted', accessToken, req)

    if(emitter.listenerCount('accessGranted') > 0){
      emitter.emit('accessGranted', req, res, next);
    } else {
      next();
    }
  }

  /**
   * If the JWT past the maximum allowable time
   * MAX = JWT.exp + REFRESH_LINGER
   *
   * @param {*} accessToken
   */
  function isPastMaxAllowableTime(accessToken){
    const EXP = JWT.decode(accessToken).exp * 1000 // seconds to milliseconds
    const MAX_ALLOWED = (new Date(EXP + CONFIG.REFRESH_LINGER)).getTime()
    const NOW = (new Date()).getTime()
    // console.log('EXP: ', EXP)
    // console.log('MAX: ', MAX_ALLOWED)
    // console.log('NOW: ', NOW)
    // console.log('old: ', NOW > MAX_ALLOWED)

    return NOW > MAX_ALLOWED
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

    if(!tokenHandler.hasSignature()){
      // Git the signature then try again
      AUTH.fetchJWTSignature()
        .then(sig => {
          tokenHandler.setSignature(sig);
          verifyJWT(req, res, next)/* try again */
        })
        .catch(err => {
          LOGGER.logRequest('Unauthorized Request: NoSignature', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        })

    // Do the actual validtion here
    } else {
      try {
        const jwt = tokenHandler.validateAccessToken(accessToken)

        // Force refresh if withing PRE_REFRESH_BUFFER buffer
        const now = (new Date()).getTime();
        if(needsRefreshed(now, jwt.exp * 1000, CONFIG.PRE_REFRESH_BUFFER)){
          throw new TokenExpiredError('Token is past PRE_REFRESH_BUFFER limit', now - CONFIG.PRE_REFRESH_BUFFER);

        } else {
          // Pass them through
          grantAccess(req, res, next)
        }

      } catch(err) {
        if (err instanceof TokenExpiredError) {
          if(isPastMaxAllowableTime(accessToken)){
            // Past MAX_ALLOWED : token is actually expired
            LOGGER.logRequest(`Expired token used: ${err}`, accessToken, req)

            if(!lingeringTokenStore.has(accessToken)) {
              // Record that we have already refreshed this token
              lingeringTokenStore.set(accessToken, 1)

              refreshAccessTokenAndReprocess(/*accessToken,*/ req, res, next)
              .then(() => {
                // Remove from linger when limit is reached
                setTimeout(() => {
                  lingeringTokenStore.delete(accessToken)
                }, CONFIG.REFRESH_LINGER)
              })
              .catch((err) => {
                // Failed to refresh remove token from linger
                lingeringTokenStore.delete(accessToken)
              })
             } else {
               grantAccess(req, res, next)
             }

          } else {
            // Allow them through because time left on linger
            grantAccess(req, res, next)
          }

        } else {
          // Call the listener 'unauthorizedRequest' handler if registered
          LOGGER.logRequest(`Unauthorized Request: ${err.name}`, accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        }
      }
    }
  }


  /**
   * Takes an expired AccessToken and exchanges it for a new one (via a
   * refreshToken). This will pass on the request (to appropriate handlers)
   * once the request for the refresh token has been fulfilled.
   *
   * Side effects:
   *  - sets the access token in req.cookie on successful refresh
   *
   * @method refreshAccessToken
   * @see returned function for params list
   */
  function refreshAccessTokenAndReprocess(/*expiredAccessToken,*/ req, res, next) {
    return requestRefreshToken(req)
            .then(tokens => {
              if (tokens.access_token){
                // Set new token on response
                tokenHandler.setTokens(res, tokens.access_token, tokens.refresh_token)
                // Pass back to verifyJWT for processing
                grantAccess(req, res, next)

              } else {
                LOGGER.debug(`-- Refresh Failed : no tokens returned from IDP refresh (refresh token had likely expired) --`)
                tokenHandler.clearTokens(res)
                AUTH.sendRefreshErrorEvent(new Error('Failed to refresh token with IDP service.'), req, res, next);
              }
            })
            .catch(err => {
              LOGGER.debug(`${color.FgRed}=== Error on refresh token: ===${color.Reset}`);
              LOGGER.debug(err.message)
              console.log(err)
              // tokenHandler.clearTokens(res)
              AUTH.sendRefreshErrorEvent(err, req, res, next);
            })
  }


  // Exposing ======================================
  return { verifyJWT }
}