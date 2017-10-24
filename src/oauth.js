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
module.exports = function(app, config, passport, logger) {
  // validate passed in config
  // required.... 
  validateConfig(config); // will throw err on invalid config

  const self = this;

  /********* Routes **********/
  /**
   * login route (root/login)
   * 
   * Logs a user in through IDP
   */
  app.get('/login', passport.authenticate('gpoauth', {
    session: true
  }), (req, res, next) => {
    console.log("USER SESSION: ", req.sessionID);
  });

  /**
   * 
   * Endpoint for exchanging a grantcode for an acessToken
   */
  app.get('/authtoken', (req, res) => {
    const oauth = {
      client_id: config.APP_ID,
      client_secret: config.APP_SECRET,
      grant_type: "authorization_code",
      code: req.query.code
    };
    
    console.log("Oauth Object: ", oauth);
    request({
      uri: config.IDP_BASE_URL + config.IDP_TOKEN_URL,
      method: 'POST',
      json: oauth
    }, function(error, response) {
      if (error) throw error;
      
      console.log("Token exchange respose: ", response.body);
      
      let profileUser = {};
      profileUser.accessToken = response.body.access_token;
      profileUser.refreshToken = response.body.refresh_token; // what to do with this guy...
      //self.accessToken = profileUser.accessToken;
      //self.refreshToken = profileUser.refreshToken;
      
      //real call
      res.redirect(`/#/lma?access_token=${response.body.access_token}&token_type=Bearer`);
    });
  });

};


// ===== Helper functions ===== //
function validateConfig(config){
  let missingFieldErr = "Invalid config passed to oauth module. Require field missing: ";

  if (!config.APP_ID) throw missingFieldErr + 'APP_ID';
  if (!config.APP_SECRET) throw missingFieldErr + 'APP_SECRET';
  if (!config.IDP_BASE_URL) throw missingFieldErr + 'IDP_BASE_URL';
  if (!config.IDP_BASE_URL) throw missingFieldErr + 'IDP_BASE_URL';
  if (!config.IDP_TOKEN_URL) throw missingFieldErr + 'IDP_TOKEN_URL';
  if (!config.LOGIN_URL) throw missingFieldErr + 'LOGIN_URL'

  return true;
}