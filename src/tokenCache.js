const mongo = require('mongodb').MongoClient
const color = require('./consoleColors.js')

/**
 * TokenCache
 *
 * The token cache is a simple cache for keeping refresh tokens that are
 * related to a token coming from the server. The simple cache allows us to
 * keep record of a users current refresh token for refreshing their
 * access token (JWT) that has a much shorter lifespan.
 */
module.exports = function(CONFIG) {
  const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);


  /**
   * Associative Array of:
   * {
   *    String<AccessToken>: String<RefreshToken>
   * }
   *
   * We use Access Tokens as keys because we are able to validate them with the
   * ignature and therefore garentee that only valid keys are maintained in the
   * cache.
   */
  let cache = {};

  // Attempt to connect to mongo store
  if(!!CONFIG.TOKEN_CACHE_HOST){
    const CREDS = CONFIG.TOKEN_CACHE_USER ? `${CONFIG.TOKEN_CACHE_USER}:${CONFIG.TOKEN_CACHE_PASS}@` : ''
    const AUTHPARAM = CREDS.length ? `?authSource=${CONFIG.TOKEN_CACHE_AUTHDB}` : ''
    const CONN_STRING = `mongodb://${CREDS}${CONFIG.TOKEN_CACHE_HOST}:${CONFIG.TOKEN_CACHE_PORT}${AUTHPARAM}`

    mongo.connect(CONN_STRING, {
            useNewUrlParser: true,
            useUnifiedTopology: true
        },
        (err, client) => {
            if (err) {
              LOGGER.debug(`${color.FgRed}ERROR connecting to MongoDB. Falling back to in memory TokenCache implementation${color.Reset}`)
              console.log(err)
            } else {
              // Use the Mongo token cache
              const db = client.db('nodeGpoauth')
              cache = db.collection('TokenCache')
              LOGGER.debug(`${color.FgYellow}== Connected to Mongo DB for TokenCache ==${color.Reset}`)
            }
        }
    )
  } else {
    LOGGER.debug("== Using local in memory TokenCache implementation ==")
  }

  /**
   * For typeguard, are use using Mongo or local.
   */
  function isMongoCache(){
    return cache && typeof cache.updateOne == 'function'
  }




  /**
   * Add an token to the cache
   */
  async function add(accessToken, refreshToken, expiration) {
    switch (isMongoCache()) {
      case true:
        const query = { 'accessToken': accessToken }
        const update = {
          '$set': {
            'accessToken': accessToken,
            'refreshToken': refreshToken,
            'ttl': expiration
          }
        }
        return cache.updateOne(query, update, { upsert: true })

      case false:
        cache[accessToken] = {
          'refreshToken': refreshToken,
          'ttl': expiration
        };
        return Promise.resolve(cache[accessToken]);
    }
  }

  /**
   * Get a refresh token for given accessToken
   */
  async function getRefreshToken(accessToken){
    switch (isMongoCache()) {
      case true:
        return cache.findOne({ 'accessToken': accessToken })
                    .then(r => r.refreshToken)
      case false:
        return Promise.resolve(cache[accessToken] && cache[accessToken].refreshToken);
    }
  }

  /**
   * Invalidate/remove accessToken and its refreshToken from the cache
   */
  async function remove(accessToken) {
    switch (isMongoCache()) {
      case true:
        return cache.deleteOne({ 'accessToken': accessToken })

      case false:
        return delete cache[accessToken]
    }
  }

  /**
   * Clean Cache
   */
  async function cleanCache(){
    const now = new Date().getTime()
    switch (isMongoCache()) {
      case true:
        return cache.deleteMany({ 'ttl': { $lt: now } })

      case false:
        cache = Object.entries(cache)
                      .filter(([at, data]) => data.ttl < now)
                      .reduce((acc, [at, data]) => {
                        acc[at] = data
                        return acc
                      }, {})
    }
  }


  // Setup automatic cleaner: remove old tokens
  const aDay = 60 * 60 * 24 * 1000
  setInterval(cleanCache, aDay)

  // ==========================================================================

  // exposing (...)
  return {
    add,
    getRefreshToken,
    remove
  }

}