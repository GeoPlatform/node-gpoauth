# node-gpoauth

A NodeJS module used for automating the link to gpoauth's OAuth2 IDP for a NodeJS applictaion.

## Overview
Node-gpoauth is a standardized node module that can be loading into any NodeJS appliction.
Node-gpoauth does the following things:
- Automatically direct user to IDP for authentication
- Setup endpoints on your application for redirecting users for Authentication and communicating with gpoauth IDP
- Fetch Bearer token (JWT) and pass it to the browser (user)
- Automatically refresh expired tokens (JWTs) and send them to the client via a Bearer token in the Authorization header
- Validate (server side) JWT signature against IA application secret for each request
- Emit important authentication events to hosting application

The node-gpoauth moduel will setup up a few api routes for your application. These routes are:

| Endpoint | Description |
|---|---|
|/login | Endpoint that will re-direct user to IDP for authentication. |
|/authtoken | Endopint that will handle Grant Code exchange from IDP. |

<br>

## Installation

Import node-gpoauth directly from github using the following in package.json:
>npm install git+https://github.com/GeoPlatform/node-gpoauth.git

<br>

## Usage
Load and instanciate the module:
```javascript
// Modules =================================================
const express     = require('express');
const app         = express();
const nodeGpoauth = require('node-gpoauth')


// IDP (gpoauth) =========================================
const config = {
    IDP_BASE_URL: "http://gpoauth.gov",
    APP_ID: "000",
    APP_SECRET: "KILTjRrzRhitJY5CRW56s9owDEMtYCldAj4IE6NxwN",
    APP_BASE_URL: "http://coolapp.com"
  }

const IDP = nodeGpoauth(app, config);

// Setup event handlers
IDP.on('unauthorizedRequest', (req, res, next) => { 
  //... 
})
```

## Setup
Setting up the module requires two fields:  

| Param | Type | Description |
|---|---|---|
|app | ExpressJS app object | ExpressJS App |
|config | Object | Configuraion for the node-gpoaut. See configuration section below.|


<br><br>

## Configuration
The following are the fields that can be on the configurartion object sent to node-gpoauth.
### Required Fields

| Field | Type | Description| Example |
|---|---|---|---|
|IDP_BASE_URL| sring | The base domain for the IDP sevice | https://idp.geoplatform.gov|
|APP_ID | string | The Application ID as it was registerd with the IDP service | 105 |
|APP_SECRET | string | The Application secret that was generated with the Application was  regestered with the IDP | KILTjRrzRhitJY5CRW56s9owDEMtYCldAj4IE6NxwN |
|APP_BASE_URL | string | Base URL of the application hosted where this module is being used. This is used for redirecting the user back to your application once they have authenticated. | http://map.geoplatform.gov |

### Optional Fields

| Field | Type | Description| Example |
|---|---|---|---|
|SERVICE_NAME| string | The name of the Application hosting this module | Map_Service|
|DEBUG| boolean | If true print out debug information from node-gpoauth | true|

<br><br>

## Events
The following events are emitted from the module that allow the hosting Application to respond to IDP events. See the Usage section for an example of seting up an event handler. Avaliable events are:
  
> ## unauthorizedRequest (required)
> This event is called with an unauthorized request is made to your application. It will only be called in the event that the client (browser) making the request does not have a valid JWT. Depending on how your application is set up you may want to filter only some requests. For example, if your application servers both static assets as well as an API you will only want to limit access to the API. You application is required to implement a handler for this event. If there is no registered event handler for this event node-gpoauth will throw and error.
>
>**NOTE:**   
>Failing to either call the next funcation or send a response to the client will cause the application to hang as Express will not continue processing the request middleware.
>
>**Parameters:**
>
>| Name | Type | Description |
>|---|---|---|
>|err | Error | The error encountered when validating the JWT. |
>|req | ExpressJS Request | The ExpressJS Requests object. |
>|res | ExpressJS Response | The ExpressJS Response object. |
>|next| Function | ExpressJS middleware next function. This function must be called for the application to continue with the middleware calls. Calling this function will allow a passthrough and Express will continue with serving the request|
>
>
>**Example:**
>```javascript
>IDP.on('unauthorizedRequest', (err, req, res, next) => {
>
>  // Determine the endpoints that require a valid JWT
>  if(req.originalUrl.match(/api\/.+/)) {
>    // protect API endpoint from unauthenticated users
>    res.status(401).send({
>      error: 'Unauthenticated'
>    })
>
>  } else {
>    // Allow static assets to be served without a valid JWT
>    next();
>  }
>})
>```
---
> ## errorRefreshingAccessToken (optional)
> This event is called when node-gpoauth was not able to successfully refresh an accessToken. This usually happnens when either node-gpoauth does not have a refreshToken associated to the accessToken or when the gpoauth server refused to grant another access token.
>
>**NOTE:**   
>By default, if this event is not implemented the request will be treated as a regular unauthenticaedRequest and will be handeled by that event.
>
>**Parameters:**
>
>| Name | Type | Description |
>|---|---|---|
>|err | Error | The error encountered when validating the JWT. |
>|req | ExpressJS Request | The ExpressJS Requests object. |
>|res | ExpressJS Response | The ExpressJS Response object. |
>|next| Function | ExpressJS middleware next function. This function must be called for the application to continue with the middleware calls. Calling this function will allow a passthrough and Express will continue with serving the request|
>
>
>**Example:**
>```javascript
>IDP.on('errorRefreshingAccessToken', (err, req, res, next) => {
>  if(/*allowRequest*/) {
>    next();
>  } else {
>    res.status(401).send({ 
>      err: "Refresh token expired, unable to complete request." 
>    })
>  } 
>})
>```
---

>## userAuthenticated (optional)
>Event that is fired when a user is authenticated to IDP through your application. The event will only fire when a user completes the redirect back to your application after logging into the IDP (it will not happen per request for already authenticted users). This event is useful for creating a user in your system (or linking an existing user in your system) with an IDP user.  
>
>**Parameters:**
>
>| Name | Type | Description |
>|---|---|---|
>|user | User | The user passed back from the IDP service (See example above for Object properties) |
> 
> **Example:** 
> ```javascript
>IDP.on('userAuthenticated', user => {
>  // Register/link IDP user with application user
>  user === {
>    "_id": "KILTjRrzRhitJY5CRW56s9owDEMtYCldAj4IE6NxwN",
>    "modificationDate": "2017-10-27T13:47:42.207Z",
>    "creationDate": "2017-07-24T19:13:45.730Z",
>    "username": "user",
>    "title": "",
>    "firstName": "Application",
>    "lastName": "User",
>    "middleName": "",
>    "email": "user@email.com",
>    "appRole": "admin",
>    "__v": 0,
>    "lastLogin": "2017-10-27T13:47:42.205Z",
>    "resetHash": null,
>    "resetExp": null,
>    "appSettings": [],
>    "auditLog": [],
>    "lockoutCount": 7,
>    "lockedOut": false
>  }
>})
>```
---

>## accessTokenRevoked (optional)
>Event called with a user's access has been revoked (usually user initiated).
>
>**Parameters:**
>
>| Name | Type | Description |
>|---|---|---|
>|jwt | JWT | The revoked JWT |
>|revokedToken | AccessToken | The raw token that was revoked |
> 
> **Example:** 
> ```javascript
>IDP.on('accessTokenRevoked', (jwt, revokedToken) => {
>  // handle event here
>})
>```


