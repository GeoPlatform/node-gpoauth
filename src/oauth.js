const request = require('request');
const color = require('./consoleColors.js')
const tokenCache = require('./tokenCache.js');
const jwt = require('jsonwebtoken');

/**
 * oauth.js
 *
 * Module for interacting with the Oauth provider.
 *
 * @param {Object} CONFIG - node-gpoauth configuration
 * @param {Object} emitter - instanciated Events object
 */
module.exports = function(CONFIG, emitter){

  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);

  /**
  * Attempt to fetch signature from auth using the APP_ID and APP_SECRET
  *
  * @method fetchJWTSignature
  * @returns {Promise<string>} the signature or cause of error
  */
  function fetchJWTSignature(){
    LOGGER.debug("-- Fetching signature from gpoauth (for verifying JWTs) -- ")
    return new Promise((resolve, reject) => {

      // Request signature
      request.post(CONFIG.IDP_BASE_URL + '/api/signature',
        // POST data
        {
          form: {
            client_id: CONFIG.APP_ID,
            client_secret: CONFIG.APP_SECRET
          }
        },
        // Handler
        function(error, response, rawBody) {
          if(error) {
            LOGGER.debug(`${color.FgRed}Error retrieving signature from gpoauth${color.Reset}`)
            reject(LOGGER.formalConfigError(['Not able to connect to gpoauth and fetch signature for JWT validation\n',
                      'Please check your settings passed to node-gpoauth and that the gpoauth server is running.\n',
                      ].join(''),
                      error));
          }

          try{
            var body = JSON.parse(rawBody)
          } catch(err){
            LOGGER.debug(`${color.FgRed}Error parsing signature response${color.Reset}: ${rawBody}`)
            reject(LOGGER.formalConfigError('Was not to parse signature from gpoauth.\n', 'This likely means the APP_ID and APP_SECRET are incorrect.'))
          }

          if (!body || !body.secret) {
            LOGGER.debug(`${color.FgRed}Error retrieving signature from gpoauth${color.Reset}`)
            reject(LOGGER.formalConfigError(['No signature returned from gpoauth.\n' +
                            'This likely means the APP_ID and APP_SECRET are either ',
                            'invalid or not registed with the gpoauth server.',
                            ].join(''),
                            error));
          } else {
            LOGGER.debug(`${color.FgYellow}-- Signature obtained and stored --${color.Reset}`)
            resolve(Buffer.from(body.secret, 'base64').toString())
          }
      });
    })
  }

  /**
   * Request token from Oauth2 server. Any token type can be requested.
   * Passed in params combo can be used per the token type requested:
   *
   * Client Credential Grant Example:
   * requestToken({
   *    grant_type: "client_credential",
   *    username: "MyUser",
   *    password: "MyPassword1"
   * })
   *
   * AuthorizationCode Example:
   * requestToken({
   *    grant_type: "authorization_code",
   *    code: "1234567890..."
   * })
   *
   * RefreshToken Example:
   * requestToken({
   *    grant_type: "refresh_token",
   *    refresh_token: "1234567890..."
   * })
   *
   * @method requestToken
   * @param {Object} params
   *
   * @returns {Promise} result - Error or Token response from Oauth2 server
   */
  function requestToken(params){
    // Data required for all requests
    const defaults = {
      client_id: CONFIG.APP_ID,
      client_secret: CONFIG.APP_SECRET,
    };
    // Combine defaults and passed in user data.
    const postData = Object.assign(defaults, params)

    return new Promise((resolve, reject) => {
      request({
        uri: CONFIG.IDP_BASE_URL + CONFIG.IDP_TOKEN_URL,
        method: 'POST',
        json: postData
      }, function(error, response) {
        error ?
          reject(error) :
          resolve(response.body);
      });
    })
  }


  /**
   * Request an AccessToken (and RefreshToken) given a GrantCode
   *
   * @method requestTokenFromGrantCode
   * @param {String} grantCode
   * @return {Promise<Object>} Respone from Oauth2 Server.
   */
  function requestTokenFromGrantCode(grantCode){
    return requestToken({
      grant_type: 'authorization_code',
      code: grantCode
    })
  }

  /**
   * Makes call to the Oauth2 server to exchange a Refresh Token for a new
   * Access token.
   *
   * @method requestTokenFromRefreshToken
   * @param {String} refreshToken
   * @return {Promise<Object>} Respone from Oauth2 Server.
   */
  function requestTokenFromRefreshToken(refreshToken){
    return requestToken({
      grant_type: 'refresh_token',
      refresh_token: refreshToken
    })
  }

  /**
   *
   * @param {*} accessToken
   */
  function getUserProfile(accessToken){
    return new Promise((resolve, reject) => {
      request({
        uri: CONFIG.IDP_BASE_URL + '/api/profile',
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + accessToken }
      }, function(error, response) {
        error ?
          reject(error) :
          resolve(response.body);
      });
    })
  }

  /**
   * Sends a Refresh Token Error to the user (HTTP) via Express Responce object.
   *
   * @method sendRefreshErrorEvent
   * @type middleware
   * @param {Error} err
   * @param {Express.Request} req
   * @param {Express.Response} res
   * @param {function} next
   *
   * @return undefined
   */
  function sendRefreshErrorEvent(err, req, res, next){
    // Send empty Bearer token to client to clear the expired JWT
    res.header('Authorization', 'Bearer ');

    // Inform the application
    if(emitter.listenerCount('errorRefreshingAccessToken') > 0){
      const eventError = {
        error: LOGGER.formalError("Unable to exchange RefreshToken for new AccessToken"),
        idpError: err
      }
      emitter.emit('errorRefreshingAccessToken', eventError, req, res, next);
    } else {
      // Default behavior is to redirect to login if no handler registered
      emitter.emit('unauthorizedRequest', err, req, res, next);
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
     * The function assigned to refreshAccessToken. This is the callable
     * function.
     *
     * @param {AccessToken} oldAccessToken - expired AccessToken to refresh
     * @param {Request} req - Express request object
     * @param {Response} res - Express response object
     * @param {Middleware next} next - Express middleware next function
     */
    return function(oldAccessToken, req, res, next){
      if(refreshQueue[oldAccessToken]){
        // Debounce the call to fetch refresh token
        clearTimeout(refreshQueue[oldAccessToken].request)
        refreshQueue[oldAccessToken].queue.push({
          req: req,
          res: res,
          next: next
        });
      } else {
        // Add refreshQueue record if none existing for this oldAccessToken
        refreshQueue[oldAccessToken] = {
          request: null,
          queue: [{
            req: req,
            res: res,
            next: next
          }]
        }
      }
      let refreshQueueRecord = refreshQueue[oldAccessToken]
      const oldRefreshToken = tokenCache.getRefreshToken(oldAccessToken)

      if (!!oldRefreshToken) {
        // Go ahead an fetch new AccessToken
        refreshQueueRecord.request = setTimeout(() => {
          LOGGER.debug(`-- Attempting AccessToken Refresh - Token: ${LOGGER.tokenDemo(oldAccessToken)} --`)
          requestTokenFromRefreshToken(oldRefreshToken)
            .then(refResp => {
              const newAccessToken = refResp.access_token;
              const newRefreshToken = refResp.refresh_token;

              LOGGER.debug("======= New Token =======")
              LOGGER.debug('|| Access:  ' + LOGGER.tokenDemo(newAccessToken))
              LOGGER.debug('|| Refresh: ' + LOGGER.tokenDemo(newRefreshToken))
              LOGGER.debug("=========================")

              // Send new AccessToken back to the browser though the Athorization header
              res.header('Authorization', 'Bearer ' + newAccessToken);

              // Continue requests that are waiting and remove queue
              refreshQueueRecord.queue.map(reqData => {
                // Update expected data on each request
                try{
                  reqData.req.jwt = jwt.verify(newAccessToken, tokenCache.getSignature());
                  reqData.req.accessToken = newAccessToken

                  reqData.next(null) // pass processing to all requests

                } catch(err) {
                  LOGGER.debug("=== Error on refresh token: ===");
                  LOGGER.debug(err.message)
                  sendRefreshErrorEvent(err, reqData.req, reqData.res, reqData.next);
                }
              })

              // Remove old & add new refreshTokens to cache.
              tokenCache.remove(oldAccessToken);
              tokenCache.add(newAccessToken, newRefreshToken);
              delete refreshQueue[oldAccessToken];
              LOGGER.debug(`=== TokenCache updated - added: ${LOGGER.tokenDemo(newAccessToken)} | removed: ${LOGGER.tokenDemo(oldAccessToken)}`)
            })
            .catch(err => {
              LOGGER.debug(`${color.FgRed}=== Error on refresh token: ===${color.Reset}`);
              LOGGER.debug(err.message)
              sendRefreshErrorEvent(err, req, res, next);
            })
        }, CONFIG.REFRESH_DEBOUNCE);

      } else {
        LOGGER.debug(`${color.FgRed}Error on refresh token: No valid refresh token found for accessToken${color.Reset} ${LOGGER.tokenDemo(oldAccessToken)}`);
        sendRefreshErrorEvent(null, req, res, next)
      }

    }
  })();





  // ======================= Exposing ========================
  return {
    fetchJWTSignature: fetchJWTSignature,
    requestTokenFromGrantCode: requestTokenFromGrantCode,
    getUserProfile: getUserProfile,
    refreshAccessToken: refreshAccessToken
  }
}