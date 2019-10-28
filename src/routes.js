
const request = require('request');
const color = require('./consoleColors');
const jwt = require('jsonwebtoken');
const tokenHandler = require('./tokenHandler.js')

/**
 * Send accessToken to broswer via the query string.
 *
 * @param {Request} res
 * @param {String} URL
 * @param {String} accessToken
 */
function sendToken(res, URL, accessToken){
  const prefix = URL.match(/\?/) ? '&' : '?';
  res.redirect(`${URL}${prefix}access_token=${accessToken}&cachebust=${(new Date()).getTime()}&token_type=Bearer`);
}

/**
 * Pretty format a Token Response.
 *
 * @param {Object} tokenResponse
 */
function getPrettyRespone(resp){
  const LOGGER = require('./logger.js')(false);
  return {
    access_token: LOGGER.tokenDemo(resp.access_token),
    refresh_token: LOGGER.tokenDemo(resp.refresh_token),
    id_token: LOGGER.tokenDemo(resp.id_token),
    expires_in: resp.expires_in,
    token_type: resp.token_type
  }
}

/**
 * Routes
 *
 * Setup for the routes added by node-gpoauth
 *
 * @param {Object} CONFIG - node-gpoauth configuration
 * @param {Express.application} app - Express Appliction
 * @param  {Object} emitter - instanciated Events object
 */
module.exports = function(CONFIG, app, emitter){
  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);
  const AUTH = require('./oauth.js')(CONFIG, emitter)

  /*
   * TODO: allow for a prefix for endpoints
   *
   * Example:
   *  My NodeJS service uses the '[root]/login' route.
   *  Allow me to set a prefix to '/oauth' so all routes
   *  for this module are then '[root]/oauth/login' etc.
   */

  /**************** Routes ******************/
  /**
   * login route (root/login)
   *
   * Logs a user in through IDP
   */
  app.get('/login', (req, res, next) => {
    const redirectURL = req.query.redirect_url ?
                    encodeURIComponent(req.query.redirect_url) :
                    '';

    const authURL = CONFIG.IDP_BASE_URL +
                    CONFIG.IDP_AUTH_URL +
                    `?response_type=code` +
                    `&redirect_uri=` + encodeURIComponent(`${CONFIG.APP_BASE_URL}/authtoken/${redirectURL}`) +
                    `&scope=read` +
                    `&client_id=${CONFIG.APP_ID}`;

    LOGGER.debug(`Login request received: redirecting to ${color.FgBlue}${authURL}${color.Reset}`)
    if(req.query.redirect_url) LOGGER.debug(`Redirect URL set to: ${color.FgBlue}${req.query.redirect_url}${color.Reset}`)
    res.redirect(authURL)
  });

  /*
   * Endpoint for exchanging a grantcode for an accessToken
   */
  app.get('/authtoken/:redirectURL?', (req, res) => {
    LOGGER.debug(`token exchange endpoint called (/authtoken)`)

    /******** Exchange and redirect *******/
    const URL = req.params.redirectURL ?
            decodeURIComponent(req.params.redirectURL) :
            '/';
    LOGGER.debug(`URL to redirect user back to: ${color.FgBlue}${URL}${color.Reset}`)
    LOGGER.debug(`Grant code received from gpoauth: `, LOGGER.tokenDemo(req.query.code))
    LOGGER.debug(`Exchanging grant code for tokens: POST - ${CONFIG.IDP_BASE_URL + CONFIG.IDP_TOKEN_URL} | code: ${req.query.code}`)

    AUTH.requestTokenFromGrantCode(req.query.code)
      .then(tokenResp => {
        const accessToken = tokenResp.access_token;
        const refreshToken = tokenResp.refresh_token;
        tokenHandler.setTokens(res, accessToken, refreshToken)
          LOGGER.debug(`Response from exchange: `, getPrettyRespone(tokenResp))
          LOGGER.debug(`Tokens recieved: Access - ${LOGGER.tokenDemo(accessToken)} | Refresh - ${LOGGER.tokenDemo(refreshToken)}`)
          LOGGER.debug("User Authenticated - JWT:", jwt.decode(accessToken))

        // Call again to get user data and notifiy application that user has authenticated
        if(emitter.listenerCount('userAuthenticated') > 0){

          // TODO: Should avoid callback hell here...
          AUTH.getUserProfile(accessToken)
            .then(profile => {
              // Get user data here and emit auth event for applicaion
              try{
                const user = JSON.parse(profile);
                LOGGER.debug("User profile retrieved.")
                emitter.emit('userAuthenticated', user);

              } catch(e) {
                console.error(LOGGER.formalError("Error parsing user information returned from gpoauth.\nInfo retruned: " + response.body))
              } finally {
                // Send access_token to the User (browser)
                sendToken(res, URL, accessToken)
                return;
              }
            })
            .catch(err => {
              console.error(LOGGER.formalError("Error retrieving user information."))
              // Don't crash user applicaiton for this. Pass them thorugh without a token
              sendToken(res, URL, accessToken)
            })
          } else {
            // Send access_token to the User (browser)
            sendToken(res, URL, accessToken)
            return
          }
        })
        .catch(err => {
          // console.log(err)
          console.error(LOGGER.formalError("Error exchanging grant for access token (JWT)\nUser was not authenticated.", err))
          // Don't crash user applicaiton for this. Pass them thorugh without a token
          res.redirect(URL);
        })
      })


  /**
   * Endpoint that presents a loading entire applicaiton again when all
   * that we really want is to set the localstorage and call events for
   * ng-common to handle.
   */
  app.get('/auth/loading', (req, res) => {
    LOGGER.debug("Auth loading page requested")
    // sendFile not added till express 4.8.
    const fs = require('fs');
    const path = require('path')

    const html = fs.readFileSync(path.resolve(__dirname + `/html/loading.html`), 'utf8')
    res.send(html)
  });

  /**
   * Call to revoke (logout) on the gpoauth server
   */
  app.get('/revoke', (req, res, next) => {
    const accessToken = tokenHandler.getAccessToken(req);
    LOGGER.debug(`Request Revoke Token - Token : ${LOGGER.tokenDemo(accessToken)}`)

    // Make the call to revoke the token
    request({
      uri: CONFIG.IDP_BASE_URL + '/auth/revoke',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + accessToken }
    }, function(error, response) {
      if (error) res.status(500).send(error)

      tokenHandler.clearTokens(res)
      emitter.emit('accessTokenRevoked', jwt.decode(accessToken), accessToken);
        LOGGER.debug(`Token successfully revoked - Token : ${LOGGER.tokenDemo(accessToken)}`)

      res.send({ status: 'ok' }) ;
    });
  });
}