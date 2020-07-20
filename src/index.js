const configError = require('./logger.js')(false).formalConfigError;
class MyEmitter extends require('events') {}
const pkg = require('../package.json')

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
 *  - tokenHandler.js : commun functions for interacting with and persisting tokens
 */
module.exports = function(app, userConf) {
  const PARSERS = {
    BOOLEAN: parseBoolean,
    FLOAT: parseFloat,
    INT: parseInt
  }

  /**
   * Convert passed in env var (string) and parse as a boolean
   * @param {String} value
   */
  function parseBoolean(value){
    const trues = [
      'true',
      'True',
      'TRUE',
      '1'
    ]

    return typeof value === 'boolean' ?
           value :
           trues.includes(value)
  }


  /**
   * We only have to convert fields that are not strings
   */
  const fieldsToConvert = {
    // optionals
    REFRESH_DEBOUNCE: PARSERS.INT,
    PRE_REFRESH_BUFFER: PARSERS.INT,
    REFRESH_LINGER: PARSERS.INT,
    AUTH_DEBUG: PARSERS.BOOLEAN,
    AUTH_DEV_MODE: PARSERS.BOOLEAN,
    // Token Cache
    TOKEN_CACHE_PORT: PARSERS.INT,
  }


  /**
   * User Configuration with the correct types
   */
  const typeParsedConfig = Object.assign({}, Object.entries(userConf)
                                .map(([field, value]) => {
                                  const valueAsType = fieldsToConvert[field] ?
                                                      fieldsToConvert[field](value) :
                                                      value
                                  return [field, valueAsType]
                                })
                                .reduce((acc, [field, value]) => {
                                  acc[field] = value
                                  return acc
                                }, {}))

  // Validate passed in config
  validateUserConfig(userConf); // will throw err on invalid config


  /**
   * Standard default values
   */
  const defaults = {
    IDP_TOKEN_URL: "/auth/token",
    IDP_AUTH_URL: '/auth',
    AUTH_TYPE: "grant",
    SCOPES: 'read',

    // Optional
    COOKIE_DOMAIN: '.geoplatform.gov',
    REFRESH_DEBOUNCE: 250,
    PRE_REFRESH_BUFFER: 250,
    REFRESH_LINGER: 250,
    AUTH_DEBUG: false,
    AUTH_DEV_MODE: false,

    // Token Cache
    TOKEN_CACHE_PORT: 27017,
    TOKEN_CACHE_AUTHDB: 'admin'
  }

  // Combine userConfig and constants for full config
  const CONFIG = Object.assign(defaults, typeParsedConfig)

  const tokenHandler = require('./tokenHandler.js')(CONFIG)
  const emitter = new MyEmitter();  // Event Emitter
  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);
  const AUTH = require('./oauth.js')(CONFIG, emitter)
  const routes = require('./routes')(CONFIG, app, emitter, tokenHandler)
  const middleware = require('./middleware.js')(CONFIG, emitter, tokenHandler)

  // Setup Middleware ==========================================
  app.use(middleware.verifyJWT)

  /**
   * Simlple check endpoint that will be caught by middleware and allow for
   * token refreshing.
   *
   * NOTE:
   *   Must be AFTER middleware is applied
   *   (This endpoint is not included in the routes page because we want this
   *   endpoint subbject to the middleware call that will force a refresh)
   */
  app.get('/checktoken', (req, res, next) => {
    res.send({ valid: req.accessToken ? true : false })
  });

  // Attempt to obtaion signature immediatly
  AUTH.fetchJWTSignature()
    .then(sig => tokenHandler.setSignature(sig))
    .catch(err => console.error(err))

    LOGGER.debug(` ======== node-gpoauth - ${pkg.version} ======== `)
    LOGGER.debug('  Debugger Enabled ')
    LOGGER.debug('Config: ')
    LOGGER.debug(CONFIG)

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