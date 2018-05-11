const configError = require('./logger.js')(false).formalConfigError;
class MyEmitter extends require('events') {}
const tokenCache = require('./tokenCache.js')

/**
 * Node-gpoauth
 *
 * NPM package for linking up a server based NodeJS application with
 * an Oauth2 Identity provider.
 *
 * For using this package in your application please visit:
 *    https://github.com/GeoPlatform/node-gpoauth
 *
 *
 * General Structure of appliction:
 *  - index.js : bootstraper
 *  - oauth.js : for all interactions with Oauth2 Identity provider
 *  - middleaware.js : code for middleware calls added by node-gpaouth
 *  - routes.js : code for all Express routes/endpoints added by node-gpoauth
 *  - logger.js : Application and error logger
 *  - tokenCache.js : in memory store of access and refresh tokens
 */
module.exports = function(app, userConf) {

  const defaults = {
    IDP_TOKEN_URL: "/auth/token",
    IDP_AUTH_URL: '/auth/authorize',
    AUTH_TYPE: "grant",
    CALLBACK: "http://localhost:3456/authtoken",
    SCOPES: 'read',
    REFRESH_DEBOUNCE: 250 // debounce delay
  }

  // Validate passed in config
  validateUserConfig(userConf); // will throw err on invalid config
  // Combine userConfig and constants for full config
  const CONFIG = Object.assign(defaults, userConf)

  const emitter = new MyEmitter();  // Event Emitter
  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);
  const AUTH = require('./oauth.js')(CONFIG, emitter)
  const routes = require('./routes')(CONFIG, app, emitter)

  require('./middleware.js')(CONFIG, app, emitter) // setup middleware

  // Attempt to obtaion signature immediatly
  AUTH.fetchJWTSignature()
    .then(sig => tokenCache.setSignature(sig))
    .catch(err => console.error(err))

    LOGGER.debug(' ======== Debugger enabled ======== ')
    LOGGER.debug('Config: ', CONFIG)

    console.log("")
    console.log(" --> Up <-- ")
    console.log("")

  /*** Expose emitter so application can subscribe to events ***/
  return emitter;
};



/**
 * Validate a configuarion to make aure requied fields are present/valid
 *
 * @method validateUserConfig
 * @param {Object} config - config to verify
 * @return undfined
 * @throws {Error} err - Error with message related to invalid configuration
 */
function validateUserConfig(config){
  let missingFieldErr = "Invalid config passed to node-gpoauth module.\n     Require field missing: ";

  if (!config.IDP_BASE_URL) throw configError(missingFieldErr + 'IDP_BASE_URL');
  if (!config.APP_ID) throw configError(missingFieldErr + 'APP_ID');
  if (!config.APP_SECRET) throw configError(missingFieldErr + 'APP_SECRET');
  if (!config.APP_BASE_URL) throw configError(missingFieldErr + 'APP_BASE_URL');

  return true;
}