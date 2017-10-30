const request = require('request');
const jwt = require('jsonwebtoken')

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


  /************ Event Emitter ***************/
  class MyEmitter extends require('events') {}
  const emitter = new MyEmitter();



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


  /**************** Middleware ****************/
  function unsafeDecoder(req, res, next) {
    const raw = (req.headers.authorization || '').replace('Bearer ','');
    const decoded = jwt.decode(raw); 

    if(decoded) {
      req.jwt = decoded
      next();
    } else {
      // Call the listener if registered
      if(emitter.listenerCount('unauthorizedRequest') > 0){
        emitter.emit('unauthorizedRequest', req, res, next);
      } else {
        next(); // No handler -- continue process
      }
    }

  }

  function verifyJWT(req, res, next) {
    //TODO: verify JWT has not been tampered with
    // reject requset (redirect to login if invalid)
  }

  app.use(unsafeDecoder)
  // app.use(verifyJWT)



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