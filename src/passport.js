/*
 * Author: Gate Jantaraweragul
 * Created: 9/28/17
 *
 * Purpose:
 * Setup Passport middleware for user serialization and deserialization
 * Configure and set passport strategies
 *
 */
const passport = require('passport')
      Oauth2Strategy = require('passport-oauth2').Strategy,
      refresh = require('passport-oauth2-refresh');
      BearerStrategy = require('passport-http-bearer').Strategy;

module.exports = function(config){

  passport.use('refresh', new BearerStrategy(function(token, done) {
    console.log(token)
    done(null, false)
    var decoded = jwt.verify(token, jwtSecret, {ignoreExpiration: true});
      if (!decoded) return done(null, false);
      console.log("Decoded value: ", decoded);
      User.findOne({
        userId: decoded.sub
      }, function(err, user) {
        if (err) return done(err);
        if (user) {
          return done(null, user, decoded.scope);
        } else {
          return done(null, false);
        }
      })
  }));
  
  var gpOauthStrat = new Oauth2Strategy({
    authorizationURL: config.IDP_BASE_URL + config.IDP_AUTH_URL,
    tokenURL: config.IDP_BASE_URL + config.IDP_TOKEN_URL,
    clientID: config.APP_ID,
    clientSecret: config.APP_SECRET,
    scope: config.SCOPES,
    response_type: 'token',
    callbackURL: config.APP_BASE_URL + (config.PORT ? ':' + config.PORT : '') + '/authtoken'
  }
  , function(accessToken, refreshToken, profile, done) {
      // console.log(profile);
    }
  );

  passport.use('gpoauth', gpOauthStrat);
  refresh.use('gpoauth', gpOauthStrat);

  // Expose the passport setup
  return passport;
}
