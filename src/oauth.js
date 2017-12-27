const request = require('request');
const jwt = require('jsonwebtoken');
let tokenCache = require('./tokenCache.js');

/************ Event Emitter ***************/
class MyEmitter extends require('events') {}
const emitter = new MyEmitter();

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
  
  // Combine userConfig and constants for full config
  const config = Object.assign({}, {
    IDP_TOKEN_URL: "/auth/token",
    IDP_AUTH_URL: '/auth/authorize',
    AUTH_TYPE: "grant",
    CALLBACK: "http://localhost:3456/authtoken",
    SCOPES: 'read'
  }, userConf)

  // Create the passport setup
  const passport = require('./passport.js')(config);


  /********* Signature Verification *********/
  var oauth_signature = '';
  request.post(config.IDP_BASE_URL + '/api/signature',
    // POST data
    { 
      form: {
        client_id: config.APP_ID,
        client_secret: config.APP_SECRET
      }
    }, 
    // Handler
    function(error, response, rawBody) {
      if(error) { 
        throw new Error(['Not able to connect to gpoauth and fetch signature for JWT validation\n',
                  'Please check your settings passed to node-gpoauth and that the gpoauth server is running.\n',
                  'See: https://github.com/GeoPlatform/node-gpoauth#usage for config options and settings.'
                  ].join(''),
                  error);
      }
      const body = JSON.parse(rawBody)
      if (!body.secret) { 
        throw new Error(['No signature returned from gpoauth.\n' +
                        'This likely means the APP_ID and APP_SECRET are either', 
                        'invalid or not registed with the gpoauth server.', 
                        ].join(''),
                        error);
      } else {
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
    const accessToken = getToken(req);

    try {
      const decoded = jwt.verify(accessToken, oauth_signature); 
      req.jwt = decoded
      next();

    } catch(err) {

      // Automatically do the refresh if token has expired
      if (err instanceof jwt.TokenExpiredError) {
        // console.log('Expired: ', tokenDemo(accessToken || 'XXXX -- XXXX'))
        refreshAccessToken(accessToken, req, res, next);

      // Call the listener 'unauthorizedRequest' handler if registered
      } else if(emitter.listenerCount('unauthorizedRequest') > 0){
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
        next(new Error(msg)); // Fail if no handler setup
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
  app.get('/login', passport.authenticate('gpoauth', {
    session: true
  }), (req, res, next) => {});

  /**
   * Call to revoke (logout) on the gpoauth server
   */
  app.get('/revoke', (req, res, next) => {
    const accessToken = getToken(req);

    // Make the call to revoke the token
    request({
      uri: config.IDP_BASE_URL + '/auth/revoke',
      method: 'GET',
      headers: { 'Authorization': 'Bearer ' + accessToken }
    }, function(error, response) {
      if (error) {
        throw error;
        res.status(500).send(error);
      }

      tokenCache.remove(accessToken)
      emitter.emit('accessTokenRevoked', jwt.decode(accessToken), accessToken);

      // May want to force redirect here at some point
      // res.redirect(`/#/login?access_token=null`);
      res.send({ status: 'ok' })
    });
  });

  /*
   * Endpoint for exchanging a grantcode for an accessToken
   */
  app.get('/authtoken', (req, res) => {
    const oauth = {
      client_id: config.APP_ID,
      client_secret: config.APP_SECRET,
      grant_type: "authorization_code",
      code: req.query.code
    };

    request({
      uri: config.IDP_BASE_URL + config.IDP_TOKEN_URL,
      method: 'POST',
      json: oauth
    }, function(error, response) {
      if (error) throw error;

      // what to do with this guy...
      const accessToken = response.body.access_token;
      const refreshToken = response.body.refresh_token;

      // cache the refreshToken
      tokenCache.add(accessToken, refreshToken)

      // Call again to get user data and notifiy application that user has authenticated
      // TODO: Should avoid callback hell here...
      request({
        uri: config.IDP_BASE_URL + '/api/profile',
        method: 'GET',
        headers: { 'Authorization': 'Bearer ' + accessToken }
      }, function(error, response) {
        if (error) throw error;
        // Get user data here and emit auth event for applicaion
        emitter.emit('userAuthenticated', JSON.parse(response.body));

        // Send access_token to the User (browser)
        res.redirect(`/#/login?access_token=${accessToken}&token_type=Bearer`);
      });

    });
  });



  /*** Expose Events so application can subscribe ***/
  return emitter;
};




// ===== Helper functions ===== //
function validateUserConfig(config){
  let missingFieldErr = "Invalid config passed to oauth module. Require field missing: ";

  if (!config.IDP_BASE_URL) throw missingFieldErr + 'IDP_BASE_URL';
  if (!config.APP_ID) throw missingFieldErr + 'APP_ID';
  if (!config.APP_SECRET) throw missingFieldErr + 'APP_SECRET';
  if (!config.APP_BASE_URL) throw missingFieldErr + 'APP_BASE_URL';

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
  const delay = 200; // debounce delay

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

    refreshQueueRecord.request = setTimeout(() => {
      refresh.requestNewAccessToken('gpoauth', oldRefreshToken, (err, newAccessToken, newRefreshToken) => {
        if(!err && newAccessToken){
          // console.log("==== New Token ====")
          // console.log('|| Access:  ' + tokenDemo(newAccessToken))
          // console.log('|| Refresh: ' + tokenDemo(newRefreshToken))
          // console.log("===================")

          // Send new AccessToken back to the browser though the Athorization header
          res.header('Authorization', 'Bearer ' + newAccessToken);

          // Remove old & add new refreshTokens to cache.
          tokenCache.remove(oldAccessToken);
          tokenCache.add(newAccessToken, newRefreshToken);

        } else {
          // console.log("=== Error on refresh token: ===");
          // console.log(err)
          if(emitter.listenerCount('errorRefreshingAccessToken') > 0){
            const eventError = {
              error: new Error("Unable to exchange RefreshToken for new AccessToken"),
              idpError: err
            }
            emitter.emit('errorRefreshingAccessToken', eventError, req, res, next);
          } else {
            // Default behavior is to redirect to login if no handler registered
            res.redirect(`/login`);
          }
        }

        // Continue requests that are waiting and remove queue
        refreshQueueRecord.queue.map(next => next(err)) // pass processing to all requests
        delete refreshQueue[oldAccessToken];

      })
    }, delay);

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

function tokenDemo(token){
  const len = token.length
  return `${token.substring(0,4)}...[${len}]...${token.substring(len-4)}`
}