/**
 * TokenCache
 * 
 * The token cache is a simple cache for keeping refresh tokens that are 
 * related to a token coming from the server. The simple cache allows us to
 * keep record of a users current refresh token for refreshing their 
 * access token (JWT) that has a much shorter lifespan.
 * 
 * 
 */

/**
 * Associative Array of: 
 * { 
 *    Access Tokens: Refresh Token
 * }
 * 
 * We use Access Tokens as keys because we are able to validate them with the
 * ignature and therefore garentee that only valid keys are maintained in the
 * cache.
 */
let cache = {}

// Cache clear

module.exports = {
  /**
   * Add an token to the cache
   */
  add: function(accessToken, refreshToken) {
    cache[accessToken] = refreshToken;
  },

  /**
   * Get a refresh token for given accessToken
   */
  getRefreshToken: function(accessToken){
    return cache[accessToken]
  },

  /**
   * Fetch and delete record from cache
   */
  pop: function(accessToken){
    // ES6 computer property key
    const val = this.get(accessToken)
    this.remove(accessToken)
    return val;
  },

  /**
   * Invalidate/remove accessToken and its refreshToken from the cache
   */
  remove: function(accessToken) {
    delete cache[accessToken]
  }
}