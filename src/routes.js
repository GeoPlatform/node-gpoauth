
const request = require('request');
const color = require('./consoleColors');
const tokenCache = require('./tokenCache');
const jwt = require('jsonwebtoken');

/**
 * Get the accessToken from request.
 *
 * @param {Request} req
 */
function getToken(req){
  return (req.headers.authorization || '').replace('Bearer ','');
}

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
    let redirectURL;
    if(req.query.sso){
      redirectURL = `?sso=true`
      LOGGER.debug(`Single Sign On (SSO) login requested`)
    } else {
      // TODO: Should refactor to remove the odd double URI encoding of redirect_url
      redirectURL = req.query.redirect_url ?
                      encodeURIComponent(req.query.redirect_url) :
                      '';
    }

    const authURL = CONFIG.IDP_BASE_URL +
                    CONFIG.IDP_AUTH_URL +
                    `?response_type=code` +
                    `&redirect_uri=` + encodeURIComponent(`${CONFIG.APP_BASE_URL}/authtoken/${redirectURL}`) +
                    `&scope=read` +
                    `&client_id=${CONFIG.APP_ID}` +
                    (req.query.sso ? '&sso=true' : '');

    LOGGER.debug(`Login request received: redirecting to ${color.FgBlue}${authURL}${color.Reset}`)
    if(req.query.redirect_url) LOGGER.debug(`Redirect URL set to: ${color.FgBlue}${req.query.redirect_url}${color.Reset}`)
    res.redirect(authURL)
  });

  /*
   * Endpoint for exchanging a grantcode for an accessToken
   */
  app.get('/authtoken/:redirectURL?', (req, res) => {
    LOGGER.debug(`token exchange endpoint called (/authtoken)`)

    // Catch SSO test and redirect to page close script
    if(req.query && req.query.sso && JSON.parse(req.query.sso) && !req.query.code){
      // Send them an HTML file that communicates with ng-common to close SSO iframe
      LOGGER.debug(`${color.FgRed}SSO login attempt failed${color.Reset}`)
      res.send(
        `<!DOCTYPE html>
        <html lang="en">
        <head>
          <meta charset="UTF-8">
          <title>Close Iframe!</title>
        </head>
        <body>
          <p>This is a code generated page</p>
          <p>Please go back to <a href="${CONFIG.APP_BASE_URL}">${CONFIG.APP_BASE_URL}</a> to log in </p>
          <script>
            window.parent.postMessage("iframe:ssoFailed", "${CONFIG.APP_BASE_URL}");
          </script>
        </body>
        </html>`
      )
      return
    }

    /******** Exchange and redirect *******/
    let URL;

    // Fails SSO attempts will not return a grant code
    if(!req.query.code){
      LOGGER.debug(`${color.FgRed}No grant code recieved: redirecting user back${color.Reset}`)
      res.redirect(URL)
      return // end execution
    }

    if(req.query.sso){
      // Always use the auth/loading endpoint to prevent loading the applicaiton
      // again in the SSO iframe.
      URL = '/auth/loading'
    } else {
      URL = req.params.redirectURL ?
              decodeURIComponent(req.params.redirectURL) :
              '/';
    }
    LOGGER.debug(`URL to redirect user back to: ${color.FgBlue}${URL}${color.Reset}`)
    LOGGER.debug(`Grant code received from gpoauth: `, LOGGER.tokenDemo(req.query.code))
    LOGGER.debug(`Exchanging grant code for tokens: POST - ${CONFIG.IDP_BASE_URL + CONFIG.IDP_TOKEN_URL} | code: ${req.query.code}`)

    AUTH.requestTokenFromGrantCode(req.query.code)
      .then(tokenResp => {
        const accessToken = tokenResp.access_token;
        const refreshToken = tokenResp.refresh_token;
          LOGGER.debug(`Response from exchange: `, getPrettyRespone(tokenResp))
          LOGGER.debug(`Tokens recieved: Access - ${LOGGER.tokenDemo(accessToken)} | Refresh - ${LOGGER.tokenDemo(refreshToken)}`)

        // cache the refreshToken
        tokenCache.add(accessToken, refreshToken)
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
          console.error(LOGGER.formalError("Error exchanging grant for access token (JWT)\nUser was not authenticated."))
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
   * Simlple check endpoint that will be caught by middleware and allow for
   * token refreshing.
   */
  app.get('/checktoken', (req, res, next) => res.send({status: "something"}));

  /**
   * Call to revoke (logout) on the gpoauth server
   */
  app.get('/revoke', (req, res, next) => {
    const accessToken = getToken(req);
      LOGGER.debug(`Request Revoke Token - Token : ${LOGGER.tokenDemo(accessToken)}`)

    // Make the call to revoke the token
    request({
      uri: CONFIG.IDP_BASE_URL + '/auth/revoke',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + accessToken }
    }, function(error, response) {
      if (error) res.status(500).send(error)

      tokenCache.remove(accessToken)
      emitter.emit('accessTokenRevoked', jwt.decode(accessToken), accessToken);
        LOGGER.debug(`Token successfully revoked - Token : ${LOGGER.tokenDemo(accessToken)}`)

      // If sso set then redirect to the logout endpoint to destroy gpoauth cookie
      req.query.sso ?
        res.redirect(`${CONFIG.IDP_BASE_URL}/logout`) :
        res.send({ status: 'ok' }) ;
    });
  });
}