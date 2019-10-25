const jwt = require('jsonwebtoken');

/**
 * Functions for dealing with tokens.
 *  - verifications
 *  - getting
 *  - setting
 */

// =================== Constants =================== //
const ACCESS_TOKEN_COOKIE  = 'gpoauth-a'
const REFRESH_TOKEN_COOKIE = 'gpoauth-r'


// ==================== helpers ==================== //
function base64Encode(str){
    return Buffer.from(str).toString('base64')
}

function base64Decode(str){
    return Buffer.from(str, 'base64').toString('ascii')
}




// ================== Verification ================= //
let oauth_signature; // Validation signature from the oauth server

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

function validateAccessToken(accessToken){
    return jwt.verify(accessToken, oauth_signature);
}


// ============ Token Related Functions ============ //
/**
 * Get the accessToken from request.
 *
 * @param {Request} req
 */
function getAccessToken(req){
  const cookie = req.cookies
              && req.cookies[ACCESS_TOKEN_COOKIE]
              && base64Decode(req.cookies[ACCESS_TOKEN_COOKIE])
  const header = ((req.headers && req.headers.authorization) || '').replace('Bearer ','');

  return cookie || header
}

/**
 * Get a parse JWT object from cookie
 *
 * @param {Request} req
 */
function getJWT(req){
    return jwt.decode(getAccessToken(req))
}

/**
 * Get the refresh token from the Cookies!
 *
 * @param {Request} req
 */
function getRefreshToken(req){
    return req.cookies
        && req.cookies[REFRESH_TOKEN_COOKIE]
        && base64Decode(req.cookies[REFRESH_TOKEN_COOKIE])
}

/**
 * Set token(s) in the cookie
 *
 * @param {string} accessToken
 * @param {string} refreshToken
 */
function setTokens(res, accessToken, refreshToken){
    const exp = new Date(Date.now() + 1000 * 1000)
    if (accessToken)
        res.cookie(ACCESS_TOKEN_COOKIE, base64Encode(accessToken), {
            expires: exp
        })

    if (refreshToken)
        res.cookie(REFRESH_TOKEN_COOKIE, base64Encode(refreshToken), {
            expires: exp,
            httpOnly: true, // SECURITY: this is required
        })

    return res
}

/**
 * Purge tokens from the cookie.
 *
 * @param {Response} res
 */
function clearTokens(res){
    res.clearCookie(ACCESS_TOKEN_COOKIE)
    res.clearCookie(REFRESH_TOKEN_COOKIE)
}


module.exports = {
    setSignature,
    getSignature,
    validateAccessToken,
    getJWT,

    getAccessToken,
    getRefreshToken,
    setTokens,
    clearTokens
}