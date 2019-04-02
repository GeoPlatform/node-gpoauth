const request = require('request');
const color = require('./consoleColors.js')
const jwt = require('jsonwebtoken');

// DT-2491: clear revoke signal to broswer
const REVOKE_RESPONSE = '<REVOKED>';

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
   * Fetches the User's Profile from Oauth2 provider.
   *
   * @method getUserProfile
   * @param {String} accessToken
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
    res.header('Authorization', REVOKE_RESPONSE);
    LOGGER.debug("Removing browser token (empty Authorization header sent)")

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


  // ======================= Exposing ========================
  return {
    fetchJWTSignature,
    requestTokenFromGrantCode,
    requestTokenFromRefreshToken,
    getUserProfile,
    sendRefreshErrorEvent
  }
}