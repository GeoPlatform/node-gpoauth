const jwt = require('jsonwebtoken');
const TokenCache = require('./tokenCache')

module.exports = function(CONFIG) {
    const LOGGER = require('./logger.js')(CONFIG.AUTH_DEBUG);
    const CACHE = TokenCache(CONFIG)


    /**
     * Functions for dealing with tokens.
     *  - verifications
     *  - getting
     *  - setting
     */

    // =================== Constants =================== //
    const ACCESS_TOKEN_COOKIE  = 'gpoauth-a'


    // ==================== helpers ==================== //
    function base64Encode(str){
        return Buffer.from(str).toString('base64')
    }

    function base64Decode(str){
        return Buffer.from(str, 'base64').toString('ascii')
    }

    function getExpTime(){
        // 1 Day from now
        return Date.now() + (60 * 60 * 24) * 1000
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
    async function getRefreshToken(req){
        return CACHE.getRefreshToken(getAccessToken(req))
    }

    /**
     * Set token(s) in the cookie
     *
     * @param {string} accessToken
     * @param {string} refreshToken
     */
    async function setTokens(res, accessToken, refreshToken){
        if (accessToken)
            res.cookie(ACCESS_TOKEN_COOKIE, base64Encode(accessToken), {
                maxAge: getExpTime(),
                // secure: true,
                // SameSite:'Strict',
                // domain: CONFIG.COOKIE_DOMAIN
            })

        if (refreshToken)
            return  await CACHE.add(accessToken, refreshToken, getExpTime())

    }

    /**
     * Purge tokens from the cookie.
     *
     * @param {Response} res
     */
    function clearTokens(res){
        res.clearCookie(ACCESS_TOKEN_COOKIE)
        // CACHE.remove(getAccessToken(req)) // May want to make asyn some day
    }

    return {
        setSignature,
        getSignature,
        validateAccessToken,
        getJWT,

        getAccessToken,
        getRefreshToken,
        setTokens,
        clearTokens
    }
}

