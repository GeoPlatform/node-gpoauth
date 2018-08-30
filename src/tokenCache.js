/**
 * TokenCache
 *
 * The token cache is a simple cache for keeping refresh tokens that are
 * related to a token coming from the server. The simple cache allows us to
 * keep record of a users current refresh token for refreshing their
 * access token (JWT) that has a much shorter lifespan.
 */
let oauth_signature;

/**
 * Associative Array of:
 * {
 *    String<AccessToken>: {
 *      refreshToken: String<RefreshToken>
 *      newAccessToken: String<AccessToken>
 *    }
 * }
 *
 * We use Access Tokens as keys because we are able to validate them with the
 * ignature and therefore garentee that only valid keys are maintained in the
 * cache.
 */
let cache = {};

/**
 * Add an token to the cache
 */
function add(accessToken, refreshToken) {
  const entry = {
    refreshToken: refreshToken,
    newAccessToken: null
  }
  cache[accessToken] = entry;
  return entry;
}

/**
 * Get a refresh token for given accessToken
 */
function getRefreshToken(accessToken){
  return cache[accessToken] && cache[accessToken].refreshToken
}

function setNewAccessToken(accessToken, newAccessToken) {
  const data = cache[accessToken]
  data.newAccessToken = newAccessToken;
  return data
}

function hasBeenRefreshed(accessToken){
  return !!getNewAccessToken(accessToken);
}

function getNewAccessToken(accessToken){
  return cache[accessToken].newAccessToken
}

function getLatestToken(accessToken){
  return getNewAccessToken(accessToken) || accessToken;
}

/**
 * Fetch and delete record from cache
 */
function pop(accessToken){
  const val = cache[accessToken];
  remove(accessToken)
  return val;
}

/**
 * Invalidate/remove accessToken and its refreshToken from the cache
 */
function remove(accessToken) {
  delete cache[accessToken]
}

/**
 * Set the oauth_signature
 *
 * @param {String} signature
 */
function setSignature(signature) {
  oauth_signature = signature;
}

/**
 * Get the oauth_signature.
 *
 * @returns {String} the oauth signature
 */
function getSignature(){
  return oauth_signature;
}

// ==========================================================================

// exposing (...)
module.exports = {
  add,
  getRefreshToken,
  setNewAccessToken,
  hasBeenRefreshed,
  getNewAccessToken,
  getLatestToken,
  pop,
  remove,
  // =======================
  setSignature,
  getSignature
}

