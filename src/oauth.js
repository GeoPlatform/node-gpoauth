const request = require('request');

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

  const self = this;

  /********* Routes **********/
  /**
   * login route (root/login)
   * 
   * Logs a user in through IDP
   */
  app.get('/login', passport.authenticate('gpoauth', {
    session: true
  }), (req, res, next) => {});

  /**
   * 
   * Endpoint for exchanging a grantcode for an accessToken
   */
  app.get('/authtoken', (req, res) => {
    console.log('Grant Code: ', req.query.code)

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

      // console.log("Token exchange respose: ", response.body);

      // what to do with this guy...
      const refreshToken = response.body.refresh_token; 

      //real call
      res.redirect(`/#/login?access_token=${response.body.access_token}&token_type=Bearer`);
    });
  });
};




// ===== Helper functions ===== //
function validateUserConfig(config){
  let missingFieldErr = "Invalid config passed to oauth module. Require field missing: ";

  if (!config.IDP_BASE_URL) throw missingFieldErr + 'IDP_BASE_URL';
  if (!config.APP_ID) throw missingFieldErr + 'APP_ID';
  if (!config.APP_SECRET) throw missingFieldErr + 'APP_SECRET';
  if (!config.SERVICE_NAME) throw missingFieldErr + 'SERVICE_NAME';
  if (!config.APP_BASE_URL) throw missingFieldErr + 'APP_BASE_URL';

  return true;
}