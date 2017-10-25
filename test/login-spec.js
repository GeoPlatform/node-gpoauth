// Testing Deps
const assert = require('chai').assert;

// Deps
const request = require('request');



/*****  Setup  *****/
const config = {
    IDP_BASE_URL:	process.env.npm_package_config_IDP_BASE_URL,
    APP_ID:			process.env.npm_package_config_APP_ID,
    APP_SECRET:     process.env.npm_package_config_APP_SECRET,
    SERVICE_NAME:	process.env.npm_package_config_SERVICE_NAME,
}

// Test for valid settings
const NodeClient = require('./NodeClient.js')
const NODE = new NodeClient(config);
/********************/


/**
 * The actual tests
 */
describe('node-gpoauth', () => {
    
    it('should have an active gpoauth server to test against', done => {
        request({
            uri: config.IDP_BASE_URL,
            method: 'GET'
        }, (err, resp) => {
            // Fail on error
            assert.isNull(err);
            assert.equal(200, resp.statusCode);
            done();
        })
    })

    describe('Login', () => {

        it('should not allow unautorized user to access resource', done => {
            done()
        })

        it('should exchange a Grant Code for an Access Token and return it to the browser', () => {
            // make client like request to the IDP
            

            // verify 'access_token' query param set
            // verify 'token_type' === 'Bearer' query param set 
        })

        it('should allow an authorized user to access resource', done => {
            done()
        })
    })

    describe('Refresh', () => {
        it.skip('should get a new token when refreshing', () => {})
    })

    describe('Validate JWT', () => {
        it.skip('should be able to verify JWT signature', () => {})
        it.skip('should throw an error if a JWT signature is invalid (JWT tampering detected', () => {})
    })

})