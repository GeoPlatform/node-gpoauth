//passport.js

/*
 * Author: Gate Jantaraweragul
 * Created: 9/28/17
 *
 * Purpose:
 * Setup Passport middleware for user serialization and deserialization
 * Configure and set passport strategies
 *
 */

const Oauth2Strategy = require('passport-oauth2').Strategy,
      BearerStrategy = require('passport-http-bearer').Strategy,
      refresh = require('passport-oauth2-refresh'),
      jwt = require('jsonwebtoken');

module.exports = function(app, config, logger, passport){

  passport.serializeUser(function(user, done) {
    console.log("Serialize User Object: ", user);
  done(null, user._id);
  });

  passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
      done(err, user);
    });
  });  
  
  passport.use(new BearerStrategy(function(token, done) {
    // var decodedJwt = jwt.decode(token);
    // if (decodedJwt.exp * 1000 > Date.now()){
    //   return done(new Error("JWT is expired"), false);
    // }
    // jwt token auth
    jwt.verify(token, jwtSecret, function(err, decoded) {
      if (err) return done(err);
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
    })
  }));

  passport.use('refresh', new BearerStrategy(function(token, done) {
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
  
  //console.log("Appconfig sent to oauth: ", config);
  
  var gpOauthStrat = new Oauth2Strategy({
    authorizationURL: config.IDP_BASE_URL + config.IDP_AUTH_URL,
    tokenURL: config.IDP_BASE_URL + config.IDP_TOKEN_URL,
    clientID: config.APP_ID,
    clientSecret: config.APP_SECRET,
    scope: config.SCOPES,
    response_type: 'token',
    callbackURL: (config.PORT == 80) ? config.BASE_URL + '/authtoken' : config.BASE_URL + ':' + config.PORT + '/authtoken'
  }
  , function(accessToken, refreshToken, profile, done) {
      //Needs to save the user details, particularly the refreshToken
      
      console.log(profile);
      
      // User.findOrCreate({ userId: profile.id }, function (err, user) {
      //   //find and update the accessToken and refreshToken after you find/create
      //   done(err, user);
      // });
    }
  );

  passport.use('gpoauth', gpOauthStrat);
  refresh.use('gpoauth', gpOauthStrat);
  
}
