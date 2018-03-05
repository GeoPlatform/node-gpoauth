const request = require('request');
const jwt = require('jsonwebtoken');
const color = require('./consoleColors.js')
let tokenCache = require('./tokenCache.js');

/************ Event Emitter ***************/
class MyEmitter extends require('events') {}
const emitter = new MyEmitter();
const errorHeader = `${color.FgRed}========[ node-gpoauth error ]=========${color.Reset}\n`
let CONFIG;
let oauth_signature;

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
  /**
   * Attempt to fetch signature from auth using the APP_ID and APP_SECRET
   *
   * @method fetchJWTSignature
   * @param {string} app_id - APP_ID of the application
   * @param {string} app_secret - APP_SECRET of the applicaiton
   *
   * @returns {Promise<string>} the signature or cause of error
   */
  function fetchJWTSignature(app_id, app_secret){
    debug("-- Fetching signature from gpoauth (for verifying JWTs) -- ")
    return new Promise((resolve, reject) => {

      // Request signature
      request.post(CONFIG.IDP_BASE_URL + '/api/signature',
        // POST data
        {
          form: {
            client_id: app_id,
            client_secret: app_secret
          }
        },
        // Handler
        function(error, response, rawBody) {
          if(error) {
            debug(`${color.FgRed}Error retrieving signature from gpoauth${color.Reset}`)
            reject(formalConfigError(['Not able to connect to gpoauth and fetch signature for JWT validation\n',
                      'Please check your settings passed to node-gpoauth and that the gpoauth server is running.\n',
                      ].join(''),
                      error));
          }

          try{
            var body = JSON.parse(rawBody)
          } catch(err){
            debug(`${color.FgRed}Error parsing signature response${color.Reset}: ${rawBody}`)
            reject(formalConfigError('Was not to parse signature from gpoauth.\n', 'This likely means the APP_ID and APP_SECRET are incorrect.'))
          }

          if (!body || !body.secret) {
            debug(`${color.FgRed}Error retrieving signature from gpoauth${color.Reset}`)
            reject(formalConfigError(['No signature returned from gpoauth.\n' +
                            'This likely means the APP_ID and APP_SECRET are either ',
                            'invalid or not registed with the gpoauth server.',
                            ].join(''),
                            error));
          } else {
            debug(`${color.FgYellow}-- Signature obtained and stored --${color.Reset}`)
            resolve(Buffer.from(body.secret, 'base64').toString())
          }
      });
    })

  }

  // Attempt to obtaion signature immediatly
  fetchJWTSignature(CONFIG.APP_ID, CONFIG.APP_SECRET)
    .then(sig => oauth_signature = sig)
    .catch(err => console.error(err))



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
    if(req.originalUrl.match(/login/)
      || req.originalUrl.match(/revoke/)
      || req.originalUrl.match(/authtoken/)
      || req.originalUrl.match(/checktoken/)
      || req.originalUrl.match(/auth\/loading/)
    ){
      next();
      return // end execution
    }

    const accessToken = getToken(req);

    if(!oauth_signature){
      // Git the signature then try again
      fetchJWTSignature(CONFIG.APP_ID, CONFIG.APP_SECRET)
        .then(sig => {
          oauth_signature = sig;
          verifyJWT(req, res, next)/* try again*/
        })
        .catch(err => {
          logRequest('Unauthorized Request', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        })

    // Do the actual validtion here
    } else {

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

        } else {
          // Call the listener 'unauthorizedRequest' handler if registered
          logRequest('Unauthorized Request', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        }
      }
    }
  }



  // ======== Setup middleware ======== //
  app.use(verifyJWT);


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
        next(new Error(errorHeader + msg)); // Fail if no handler setup
      }
  }


  /**************** Routes ******************/
  /**
   * login route (root/login)
   *
   * Logs a user in through IDP
   */
  app.get('/login', (req, res, next) => {
    // TODO: Should refactor to remove the odd double URI encoding of redirect_url
    if(req.query.redirect_url) debug(`Redirect URL set to: ${color.FgBlue}${req.query.redirect_url}${color.Reset}`)

    let redirectURL;
    if(req.query.sso){
      redirectURL = `?sso=true`
      debug(`Single Sign On (SSO) login requested`)
    } else {
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

    debug(`Login request received: redirecting to ${color.FgBlue}${authURL}${color.Reset}`)
    res.redirect(authURL)
  });

  /*
   * Endpoint for exchanging a grantcode for an accessToken
   */
  app.get('/authtoken/:redirectURL?', (req, res) => {

    // Catch SSO test and redirect to page close script
    if(req.query && req.query.sso && JSON.parse(req.query.sso) && !req.query.code){
      // Send them an HTML file that communicates with ng-common to close SSO iframe
      debug(`${color.FgRed}SSO login attempt failed${color.Reset}`)
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
    if(req.query.sso){
      // Always use the auth/loading endpoint to prevent loading the applicaiton
      // again in the SSO iframe.
      URL = '/auth/loading'
    } else {
      URL = req.params.redirectURL ?
              decodeURIComponent(req.params.redirectURL) :
              '/';
    }
    debug(`URL to redirect user back to: ${color.FgBlue}${URL}${color.Reset}`)

    // Fails SSO attempts will not return a grant code
    if(!req.query.code){
      debug(`${color.FgRed}No grant code recieved: redirecting user back${color.Reset}`)
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
   * Endpoint that presents a loading entire applicaiton again when all
   * that we really want is to set the localstorage and call events for
   * ng-common to handle.
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
        debug(`-- Attempting AccessToken Refresh - Token: ${tokenDemo(oldAccessToken)} --`)
        refresh.requestNewAccessToken('gpoauth', oldRefreshToken, (err, newAccessToken, newRefreshToken) => {
          if(!err && newAccessToken){
            debug("======= New Token =======")
            debug('|| Access:  ' + tokenDemo(newAccessToken))
            debug('|| Refresh: ' + tokenDemo(newRefreshToken))
            debug("=========================")

            // Send new AccessToken back to the browser though the Athorization header
            res.header('Authorization', 'Bearer ' + newAccessToken);

            // Continue requests that are waiting and remove queue
            refreshQueueRecord.queue.map(reqData => {
              // Update expected data on each request
              try{
                reqData.req.jwt = jwt.verify(newAccessToken, oauth_signature);
                reqData.req.accessToken = newAccessToken

                reqData.next(err) // pass processing to all requests

              } catch(e) {
                debug("=== Error on refresh token (1): ===");
                debug(err.message)
                sendRefreshErrorEvent(err, reqData.req, reqData.res, reqData.next);
              }
            })

            // Remove old & add new refreshTokens to cache.
            tokenCache.remove(oldAccessToken);
            tokenCache.add(newAccessToken, newRefreshToken);
            delete refreshQueue[oldAccessToken];

          } else {
            debug(`${color.FgRed}=== Error on refresh token: ===${color.Reset}`);
            debug(err.message)
            sendRefreshErrorEvent(err, req, res, next);
          }

        })
      }, CONFIG.REFRESH_DEBOUNCE);

    } else {
      debug(`${color.FgRed}Error on refresh token: No valid refresh token found for accessToken${color.Reset} ${tokenDemo(oldAccessToken)}`);
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
  debug(`Sendinging token to browser: Token: ${tokenDemo(accessToken)} | URL: ${URL}`)
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
  const footer = `Please see: ${color.FgYellow}https://github.com/GeoPlatform/node-gpoauth${color.Reset}
for examples and information on configuration settings.`
  return new Error(`${errorHeader}\n${msg}\n${footer}\n\n${err}`)
}

function logRequest(status, token, req){
  debug(`${color.FgYellow}${status}${color.Reset} - Token: ${tokenDemo(token)} | ${req.method} - ${req.originalUrl}`)
}

function debug(){
  if(CONFIG.AUTH_DEBUG)
    console.log.apply(this, [`${color.FgGreen}[node-gpoauth ${(new Date()).toLocaleTimeString()}] ${color.Reset}`].concat(Array.prototype.slice.call(arguments)))
}