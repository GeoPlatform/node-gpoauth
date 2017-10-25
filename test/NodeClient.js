const express = require('express');
const app = express();

exports = module.exports = function(config) {
    // Import the module
    const gpoauth = require('../src/oauth.js')
    const IDP = gpoauth(app, config)
   
    app.get('/api/resource', (res, req) => {
        res.send({
            msg: "I am a protectecd resource."
        })
    })
    // start app ===============================================
    app.listen(3456);
}
