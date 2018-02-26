const request = require('request');
const jwt = require('jsonwebtoken');
let tokenCache = require('./tokenCache.js');

/************ Event Emitter ***************/
class MyEmitter extends require('events') {}
const emitter = new MyEmitter();
const errorHeader = `========[ node-gpoauth error ]=========\n`
let CONFIG;

/**
 * oauth module
 *
 * Stand alone module for connecting to IDP via OAuth2.
 *
 * This module will
 *
 * @param app -
 */
module.exports = function(app, userConf) {
  const self = this;
  // validate passed in config
  validateUserConfig(userConf); // will throw err on invalid config

  /*
  * TODO: allow for a prefix for endpoints
  *
  * Example:
  *  My NodeJS service uses the '[root]/login' route.
  *  Allow me to set a prefix to '/oauth' so all routes
  *  for this module are then '[root]/oauth/login' etc.
  */

  /*
   * TODO:
   *  We should use formal errors (seporate file) so we can
   *  do type checking against them in test cases.
   */

  // Combine userConfig and constants for full config
  CONFIG = Object.assign({
    IDP_TOKEN_URL: "/auth/token",
    IDP_AUTH_URL: '/auth/authorize',
    AUTH_TYPE: "grant",
    CALLBACK: "http://localhost:3456/authtoken",
    SCOPES: 'read',
    REFRESH_DEBOUNCE: 250 // debounce delay
  }, userConf)

  // Default is to pass strings :(
  CONFIG.AUTH_DEBUG = userConf.AUTH_DEBUG === 'true' || userConf.AUTH_DEBUG === true

  debug(' ======== Debugger enabled ======== ')
  debug('Config: ', CONFIG)

  // Create the passport setup
  const passport = require('./passport.js')(CONFIG);


  /********* Signature Verification *********/
  let oauth_signature = '';
  debug("-- Fetching signature from gpoauth (for verifying JWTs) -- ")
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
        debug("Error retrieving signature from gpoauth")
        throw formalConfigError(['Not able to connect to gpoauth and fetch signature for JWT validation\n',
                  'Please check your settings passed to node-gpoauth and that the gpoauth server is running.\n',
                  ].join(''),
                  error);
      }

      try{
        var body = JSON.parse(rawBody)
      } catch(err){
        debug("Error parsing signature response")
        debug(rawBody)
        throw formalConfigError('Was not to parse signature from gpoauth.\n', 'This likely means the APP_ID and APP_SECRET are incorrect.')
      }

      if (!body.secret) {
        debug("Error retrieving signature from gpoauth")
        throw formalConfigError(['No signature returned from gpoauth.\n' +
                        'This likely means the APP_ID and APP_SECRET are either ',
                        'invalid or not registed with the gpoauth server.',
                        ].join(''),
                        error);
      } else {
        debug("-- Signature obtained and stored --")
        oauth_signature = Buffer.from(body.secret, 'base64').toString()
      }
  });




  /**************** Middleware ****************/
  /**
   * Middleware for vaidating a JWT passed in the Authorization Header
   * when requesting a resource.
   *
   * This function conforms to standard Connect middleware specs.
   *
   */
  function verifyJWT(req, res, next) {
          // Pass them through on endpoints setup by gpoauth
    if(req.originalUrl.match(/ogin/)
      || req.originalUrl.match(/revoke/)
      || req.originalUrl.match(/authtoken/)
      || req.originalUrl.match(/checktoken/)
    ){
      next();
      return // end execution
    }

    const accessToken = getToken(req);

    try {
      const decoded = jwt.verify(accessToken, oauth_signature);
      req.jwt = decoded
      req.accessToken = accessToken
        logRequest('Access Granted', accessToken, req)

      if(emitter.listenerCount('accessGranted') > 0){
        emitter.emit('accessGranted', req, res, next);
      } else {
        next();
      }

    } catch(err) {
      if (err instanceof jwt.TokenExpiredError) {
        logRequest('Expired token used', accessToken, req)
        refreshAccessToken(accessToken, req, res, next);

      // Call the listener 'unauthorizedRequest' handler if registered
      } else if(emitter.listenerCount('unauthorizedRequest') > 0){
        logRequest('Unauthorized Request', accessToken, req)
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
        next(new Error(errorHeader + msg)); // Fail if no handler setup
      }
    }
  }


  // ======== Setup middleware ======== //
  app.use(verifyJWT);



  /**************** Routes ******************/
  /**
   * login route (root/login)
   *
   * Logs a user in through IDP
   */
  app.get('/login', (req, res, next) => {
    let redirectURL = req.query.redirect_url ?
                          encodeURIComponent(req.query.redirect_url) :
                          '';
      if(redirectURL.length) debug("Redirect URL set to: ", redirectURL)

    redirectURL += req.query.sso ? `${redirectURL.match(/\?/) ? '&':'?'}sso=true` : ``
      if(req.query.sso) debug(`Single Sign On (SSO) login requested`)

    const authURL = CONFIG.IDP_BASE_URL +
                    CONFIG.IDP_AUTH_URL +
                    `?response_type=code` +
                    `&redirect_uri=` + encodeURIComponent(`${CONFIG.APP_BASE_URL}/authtoken/${redirectURL}`) +
                    `&scope=read` +
                    `&client_id=${CONFIG.APP_ID}` +
                    (req.query.sso ? '&sso=true' : '');

    debug(`Login request received: redirecting to ${authURL}`)
    res.redirect(authURL)
  });

  /*
   * Endpoint for exchanging a grantcode for an accessToken
   */
  app.get('/authtoken/:redirectURL?', (req, res) => {

    const URL = req.params.redirectURL ?
                decodeURIComponent(req.params.redirectURL) :
                '/';
    debug("URL to redirect user back to: ", URL)

    // Catch SSO test and redirect to page close script
    if(req.query && req.query.sso && JSON.parse(req.query.sso) && !req.query.code){
      // Send them an HTML file that communicates with ng-common to close SSO iframe
      debug(`SSO login attempt failed`)
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

    // Fails SSO attempts will not return a grant code
    if(!req.query.code){
      debug('No grant code recieved: redirecting user back')
      res.redirect(URL)
      return // end execution
    }

    debug(`Grant code received from gpoauth: `, tokenDemo(req.query.code))
    const oauth = {
      client_id: CONFIG.APP_ID,
      client_secret: CONFIG.APP_SECRET,
      grant_type: "authorization_code",
      code: req.query.code
    };

    debug(`Exchanging grant code for tokens: POST - ${CONFIG.IDP_BASE_URL + CONFIG.IDP_TOKEN_URL} : ${JSON.stringify(oauth)}`)

    request({
      uri: CONFIG.IDP_BASE_URL + CONFIG.IDP_TOKEN_URL,
      method: 'POST',
      json: oauth
    }, function(error, response) {
      if (error){
        console.error(formalError("Error exchanging grant for access token (JWT)\nUser was not authenticated."))
        // Don't crash user applicaiton for this. Pass them thorugh without a token
        res.redirect(URL);
        return // end execution
      }

      const accessToken = response.body.access_token;
      const refreshToken = response.body.refresh_token;
        debug(`Tokens recieved: Access - ${tokenDemo(accessToken)} | Refresh - ${tokenDemo(refreshToken)}`)

      // cache the refreshToken
      tokenCache.add(accessToken, refreshToken)
        debug("User Authenticated - JWT:", jwt.decode(accessToken))

      // Call again to get user data and notifiy application that user has authenticated
      if(emitter.listenerCount('userAuthenticated') > 0){

        // TODO: Should avoid callback hell here...
        request({
          uri: CONFIG.IDP_BASE_URL + '/api/profile',
          method: 'GET',
          headers: { 'Authorization': 'Bearer ' + accessToken }
        }, function(error, response) {
          if (error) {
            console.error(formalError("Error retrieving user information."))
            // Don't crash user applicaiton for this. Pass them thorugh without a token
            sendToken(res, URL, accessToken)
            return // end execution
          }
          // Get user data here and emit auth event for applicaion
          try{
            const user = JSON.parse(response.body);
            debug("User profile retrieved.")
            emitter.emit('userAuthenticated', user);

          } catch(e) {
            console.error(formalError("Error parsing user information returned from gpoauth.\nInfo retruned: " + response.body))
          } finally {
            // Send access_token to the User (browser)
            sendToken(res, URL, accessToken)
            return;
          }
        });

      } else {
          // Send access_token to the User (browser)
          sendToken(res, URL, accessToken)
          return
      }



    });
  });

  /**
   * Endpoint that presents a loading screen while
   */
  app.get('/auth/loading', (req, res) => {
    debug("Auth loading page requested")
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
      debug(`Request Revoke Token - Token : ${tokenDemo(accessToken)}`)

    // Make the call to revoke the token
    request({
      uri: CONFIG.IDP_BASE_URL + '/auth/revoke',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + accessToken }
    }, function(error, response) {
      if (error) res.status(500).send(error)

      tokenCache.remove(accessToken)
      emitter.emit('accessTokenRevoked', jwt.decode(accessToken), accessToken);
        debug(`Token successfully revoked - Token : ${tokenDemo(accessToken)}`)

      // If sso set then redirect to the logout endpoint to destroy gpoauth cookie
      req.query.sso ?
        res.redirect(`${CONFIG.IDP_BASE_URL}/logout`) :
        res.send({ status: 'ok' }) ;
    });
  });

  /*** Expose Events so application can subscribe ***/
  return emitter;
};


// ===== Helper functions ===== //
function validateUserConfig(config){
  let missingFieldErr = "Invalid config passed to node-gpoauth module.\n     Require field missing: ";

  if (!config.IDP_BASE_URL) throw formalConfigError(missingFieldErr + 'IDP_BASE_URL');
  if (!config.APP_ID) throw formalConfigError(missingFieldErr + 'APP_ID');
  if (!config.APP_SECRET) throw formalConfigError(missingFieldErr + 'APP_SECRET');
  if (!config.APP_BASE_URL) throw formalConfigError(missingFieldErr + 'APP_BASE_URL');

  return true;
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
  // encloing scope: private variables for retunred function

  /*
   * Object for queuing refresh request (debounce). This keeps track of all
   * pending requests for a new refresh token along with all the requests
   * to the server awaiting an authentication decision.
   *
   * Schema:
   *  {
   *    accessToken: {
   *      request: , // id of function call to refresh token
   *      queue: next[] // next middleware calls awaiting auth decision
   *    },
   *    ...
   *  }
   */
  let refreshQueue = {}
  const refresh = require('passport-oauth2-refresh');

  function sendRefreshErrorEvent(err, req, res, next){
    // Send empty Bearer token to client to clear the expired JWT
    res.header('Authorization', 'Bearer ');

    // Inform the application
    if(emitter.listenerCount('errorRefreshingAccessToken') > 0){
      const eventError = {
        error: new Error(errorHeader + "Unable to exchange RefreshToken for new AccessToken"),
        idpError: err
      }
      emitter.emit('errorRefreshingAccessToken', eventError, req, res, next);
    } else {
      // Default behavior is to redirect to login if no handler registered
      emitter.emit('unauthorizedRequest', err, req, res, next);
    }
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
    if(refreshQueue[oldAccessToken]){
      // Debounce the call to fetch refresh token
      clearTimeout(refreshQueue[oldAccessToken].request)
      refreshQueue[oldAccessToken].queue.push(next);
    } else {
      // Add refreshQueue record if none existing for this oldAccessToken
      refreshQueue[oldAccessToken] = {
        request: null,
        queue: [next]
      }
    }
    let refreshQueueRecord = refreshQueue[oldAccessToken]
    const oldRefreshToken = tokenCache.getRefreshToken(oldAccessToken)

    if (!!oldRefreshToken) {
      // Go ahead an fetch new AccessToken
      refreshQueueRecord.request = setTimeout(() => {
        debug(`-- Attempting AccessToken Refresh - Token: ${tokenDemo(oldAccessToken)} --`)
        refresh.requestNewAccessToken('gpoauth', oldRefreshToken, (err, newAccessToken, newRefreshToken) => {
          if(!err && newAccessToken){
            debug("======= New Token =======")
            debug('|| Access:  ' + tokenDemo(newAccessToken))
            debug('|| Refresh: ' + tokenDemo(newRefreshToken))
            debug("=========================")

            // Send new AccessToken back to the browser though the Athorization header
            res.header('Authorization', 'Bearer ' + newAccessToken);

            // Remove old & add new refreshTokens to cache.
            tokenCache.remove(oldAccessToken);
            tokenCache.add(newAccessToken, newRefreshToken);

            // Continue requests that are waiting and remove queue
            refreshQueueRecord.queue.map(next => next(err)) // pass processing to all requests
            delete refreshQueue[oldAccessToken];

          } else {
            debug("=== Error on refresh token: ===");
            debug(err.message)
            sendRefreshErrorEvent(err, req, res, next);
          }

        })
      }, CONFIG.REFRESH_DEBOUNCE);

    } else {
      debug(`Error on refresh token: No valid refresh token found for accessToken ${tokenDemo(oldAccessToken)}`);
      sendRefreshErrorEvent(null, req, res, next)
    }

  }
})();

/**
 * Get the accessToken from request.
 *
 * @param {Request} req
 */
function getToken(req){
  return (req.headers.authorization || '').replace('Bearer ','');
}

function sendToken(res, URL, accessToken){
  const prefix = URL.match(/\?/) ? '&' : '?';
  debug(`Sendinging token to browser: ${tokenDemo(accessToken)}`)
  res.redirect(`${URL}${prefix}access_token=${accessToken}&cachebust=${(new Date()).getTime()}&token_type=Bearer`);
}

function tokenDemo(token){
  const len = token && token.length
  return len ?
        `${token.substring(0,4)}..[${len}]..${token.substring(len-4)}` :
        '[No token]'
}

function formalError(msg, err){
  return new Error(`${errorHeader}\n${msg}\n\n${err}`)
}

function formalConfigError(msg, err){
  const footer = ['Please see:\n',
        '    https://github.com/GeoPlatform/node-gpoauth\n',
        'for examples and information on configuration settings.']
        .join('')
  return new Error(`${errorHeader}\n${msg}\n${footer}\n\n${err}`)
}

function logRequest(status, token, req){
  debug(`${status} - Token: ${tokenDemo(token)} | ${req.method} - ${req.originalUrl}`)
}

function debug(){
  if(CONFIG.AUTH_DEBUG)
    console.log.apply(this, [`[node-gpoauth ${(new Date()).toLocaleTimeString()}] `].concat(Array.prototype.slice.call(arguments)))
}