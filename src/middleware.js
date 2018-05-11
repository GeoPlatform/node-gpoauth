const jwt = require('jsonwebtoken');
const tokenCache = require('./tokenCache.js');

/**
 * Get the accessToken from request.
 *
 * @param {Request} req
 */
function getToken(req){
  return (req.headers.authorization || '').replace('Bearer ','');
}

/**
 * node-gpoauth middleware
 *
 * @param {Object} CONFIG - node-gpoauth configuration
 * @param {Express.application} app - Express Appliction
 * @param  {Object} emitter - instanciated Events object
 */
module.exports = function(CONFIG, app, emitter){
  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);
  const AUTH = require('./oauth.js')(CONFIG, emitter)

  /**
   * Emits an UnauthorizedRequest event or an error if the event does not have
   * a registered handler.
   *
   * @method fireUnauthorizedRequest
   * @param {Error} err
   * @param {Request} req
   * @param {Response} res
   * @param {function} next
   */
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
      next(LOGGER.formalError(msg)); // Fail if no handler setup
    }
  }



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

    if(!tokenCache.getSignature()){
      // Git the signature then try again
      AUTH.fetchJWTSignature()
        .then(sig => {
          tokenCache.setSignature(sig);
          verifyJWT(req, res, next)/* try again*/
        })
        .catch(err => {
          LOGGER.logRequest('Unauthorized Request', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        })

    // Do the actual validtion here
    } else {

        try {
        const decoded = jwt.verify(accessToken, tokenCache.getSignature());
        req.jwt = decoded
        req.accessToken = accessToken
          LOGGER.logRequest('Access Granted', accessToken, req)

        if(emitter.listenerCount('accessGranted') > 0){
          emitter.emit('accessGranted', req, res, next);
        } else {
          next();
        }

      } catch(err) {
        if (err instanceof jwt.TokenExpiredError) {
          LOGGER.logRequest('Expired token used', accessToken, req)
          AUTH.refreshAccessToken(accessToken, req, res, next);

        } else {
          // Call the listener 'unauthorizedRequest' handler if registered
          LOGGER.logRequest('Unauthorized Request', accessToken, req)
          fireUnauthorizedRequest(err, req, res, next)
        }
      }
    }
  }

  // Add middleware ================================
  app.use(verifyJWT)
}