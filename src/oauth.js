const request = require('request');
const jwt = require('jsonwebtoken');
let tokenCache = require('./tokenCache.js');

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
  const refresh = require('passport-oauth2-refresh');


  /************ Event Emitter ***************/
  class MyEmitter extends require('events') {}
  const emitter = new MyEmitter();


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
      if(error) throw new Error("Unable to load signture for gpoauth IDP server")
      const body = JSON.parse(rawBody)
      if (!body.secret) { 
        throw error;
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
    const accessToken = (req.headers.authorization || '').replace('Bearer ','');

    try {
      const decoded = jwt.verify(accessToken, oauth_signature); 
      req.jwt = decoded
      next();

    } catch(err) {

      // Automatically do the refresh if token has expired
      if (err instanceof jwt.TokenExpiredError) {
        refreshAccessToken(accessToken, res, next);

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

  /*
   * Endpoint for exchanging a grantcode for an accessToken
   */
  app.get('/authtoken', (req, res) => {
    // console.log('Grant Code: ', req.query.code)

    const oauth = {
      client_id: config.APP_ID,
      client_secret: config.APP_SECRET,
      grant_type: "authorization_code",
      code: req.query.code
    };

    // console.log("Oauth Object: ", oauth);
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
        console.log(response.body)
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
 * DOCUMENT ME!
 */
const refreshAccessToken = (function(){
  // encloing scope: private variables for retunred function

  /*
   * Object for queuing refresh request (debounce):
   * {
   *    accessToken: callback[] 
   * }
   */
  let refreshQueue = {}
  let timer = null;
  const delay = 200;

  // resolving function
  return function(oldAccessToken, res, callback){
    // Debounce the call to fetch refresh token
    clearTimeout(timer)
    const oldRefreshToken = tokenCache.getRefreshToken(oldAccessToken)

    // Add to or create queue for token refresh
    if(refreshQueue[oldAccessToken]){
      refreshQueue[oldAccessToken].push(callback);
    } else {
      refreshQueue[oldAccessToken] = [callback];
    }

    timer = setTimeout(() => {
      refresh.requestNewAccessToken('gpoauth', oldRefreshToken, (err, newAccessToken, newRefreshToken) => {
        if(err || !newAccessToken){
          console.log("=== Error on refresh token: ===");
          console.log(err)
          // res.redirect(`/#/login`);
          // Need to send error to applicaiton here?
        } else {
          console.log("==== New Token ====")
          console.log('|| Access:  ' + tokenDemo(newAccessToken))
          console.log('|| Refresh: ' + tokenDemo(newRefreshToken))
          console.log("===================")

          // Send new AccessToken back to the browser though the Athorization header
          res.header('Authorization', 'Bearer ' + newAccessToken);

          // Continue requests that are waiting and remove queue
          refreshQueue[oldAccessToken]
            .map(next => next(err)) // pass processing to all requests
          delete refreshQueue[oldAccessToken];

          // Remove old & add new refreshTokens to cache.
          tokenCache.remove(oldAccessToken);
          tokenCache.add(newAccessToken, newRefreshToken);
        }
      })
    }, delay);

  }
})();

function tokenDemo(token){
  const len = token.length
  return `${token.substring(0,4)}...[${len}]...${token.substring(len-4)}`
}