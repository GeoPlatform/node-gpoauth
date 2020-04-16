const express = require('express');
const app = express();

exports = module.exports = function(config, unauthorizedRequestHandler) {
    // Import the module
    const gpoauth = require('../src/oauth.js')
    const IDP = gpoauth(app, config)

    // Setup handler if there is one present
    if(unauthorizedRequestHandler){
        IDP.on('unauthorizedRequest', (err, req, res, next) => unauthorizedRequestHandler);
    }

    // A protected resource
    app.get('/api/resource', (req, res) => {
        res.send({
            msg: "I am a protectecd resource."
        })
    })

    // start app ===============================================
    app.listen(3456);
}
