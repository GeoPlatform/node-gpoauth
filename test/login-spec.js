// Testing Deps
const chai = require('chai');
    const assert = chai.assert;
    const expect = chai.expect;

// Deps
const request = require('request');



/*****  Setup  *****/
const config = {
    IDP_BASE_URL:	process.env.npm_package_config_IDP_BASE_URL,
    APP_BASE_URL:	process.env.npm_package_config_APP_BASE_URL,
    APP_ID:			process.env.npm_package_config_APP_ID,
    APP_SECRET:     process.env.npm_package_config_APP_SECRET,
    SERVICE_NAME:	process.env.npm_package_config_SERVICE_NAME,
}

/**
 * Make a temporary app to test the service against.
 * 
 * @param {*} config 
 * @param {*} unauthorizedRequestHandler 
 */
function getTestAPP(config, unauthorizedRequestHandler){
    const NodeClient = require('./NodeClient.js')
    return NodeClient(config, unauthorizedRequestHandler);
}

/**
 * Attempt to access protected resource
 * 
 * callback params: 
 *  1. error - if error
 *  2. resp - if successful
 */
function requestProtectedResource(cb){
    request({ uri: 'http://localhost:3456/api/resource', method: 'GET' }, cb);
}

/**
 * The actual tests
 */
describe('node-gpoauth', () => {
    
    it('Should have an active gpoauth server to test against', done => {
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

    describe('Config', () => {
        let testApp; // Keep local 

        it('Should throw error if require fields are missing in the config', () => {
            const TEST = this;
            const requiredFields = [
                'IDP_BASE_URL',
                'APP_ID',
                'APP_SECRET',
                'APP_BASE_URL',
            ]
            for(let field of requiredFields){
                // Null out the object we are trying to test
                let badConfig = Object.assign({}, config, { [field]: null })
                // Expect any app with missing required params to fail
                expect(() => {
                    testApp = getTestAPP(badConfig, ()=>{});
                }).to.throw()
            }
        })

        it('Should throw an error if there is no event handler for "unauthorizedRequest"', function(done){
            testApp = getTestAPP(config) // no handler passed in

            // Assert that first unauhorized access with no handler will error
            requestProtectedResource((err, resp) => {
                assert.equal(resp.statusCode, 500, 'Should error with 500 on invalid config');
                done();
            })
        })

        it.skip('Should fail when feching signature if invalid APP_ID and/or APP_SECRET are provided', done => {
            // Broken: this is hard to test as the error is thrown Asycn after the 
            //         function has aleady returned.
            let badConfig = Object.assign({}, config, { APP_ID: 'FAKE12314', APP_SECRET: "NotReal10983" })
            // Expect invlaid APP_ID / APP_SECRET to fail
            expect(() => {
                testApp = getTestAPP(badConfig, ()=>{});
            }).to.throw()
        })

        // Reset the testApp after each run
        after(() => testApp = null) 
    })

    describe('Login', () => {

        it.skip('should not allow unautorized user to access resource', done => {
            assert.fail()
        })

        it.skip('should exchange a Grant Code for an Access Token and return it to the browser', () => {
            // make client like request to the IDP
            

            // verify 'access_token' query param set
            // verify 'token_type' === 'Bearer' query param set 
            assert.fail()
        })

        it.skip('should allow an authorized user to access resource', done => {
            assert.fail()
        })
    })

    describe('Request', () => {
        it.skip('Should results in a 401 when user requests a protected resource without a valid JWT')
    })

    describe('Refresh', () => {
        it.skip('should get a new token when refreshing', () => {})

        it.skip('should delay a response with an expired token')
    })

    describe('Validate JWT', () => {
        it.skip('should be able to verify JWT signature', () => {})
        it.skip('should throw an error if a JWT signature is invalid (JWT tampering detected)', () => {})
    })

})