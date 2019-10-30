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

| Endpoint | Description | Optional Query parameters |
|---|---|---|
| /login | Endpoint that will re-direct user to IDP for authentication. | **redirect_url**: optional url to redirct user to after authenticating <br><br> **sso**: SSO login boolean. Set to true if attempting SSO login, in this case gpoauth will automatically submit login form and login chain may fail (This is intended as a headless/no UI login attempt). |
| /authtoken | Endopint that will handle Grant Code exchange from IDP. | |
| /revoke | Endpoint for revoking JWT. This should be called on logout| **sso**: Optional boolean field. If true the request will be redirected to the gpoauth /revoke endpoint. This will reirect the request to the browser to the gpoauth login page and clear the gpoauth session cookie (required for true logout). |
| /checktoken | Endpoint that allows front end application to refresh accessToken in the event that is has expired. | |
| /auth/loading | Endpoint for showing simplified page that sets localstorage. This is desifned to work alongside ng-common to set expected variables (namly, window.localStorage.gpoauthJWT). | |


<br>

## Installation

Import node-gpoauth directly from github using the following in package.json:
>npm install git+https://github.com/GeoPlatform/node-gpoauth.git

<br>

### Development and local integration
To develop with `node-gpoauth` locally you will need to install it from you local file system. First start by checking out the codebase and then use NPM in insalll it locally:
> $ # Clone node-gpoauth
> $ git clone git@github.com:GeoPlatform/node-gpoauth.git
>
> $ # cd to your appliction (local development)
> $ cd myApp
>
> $ # install using npm (path relative to your application directory)
> $ npm install file:../node-gpoauth

<br>
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
    APP_ID: "5a720833cf282142f97d7f04",
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
|APP_ID | string | The Application ID as it was registerd with the IDP service | 5a720833cf282142f97d7f04 |
|APP_SECRET | string | The Application secret that was generated with the Application was  regestered with the IDP | KILTjRrzRhitJY5CRW56s9owDEMtYCldAj4IE6NxwN |
|APP_BASE_URL | string | Base URL of the application hosted where this module is being used. This is used for redirecting the user back to your application once they have authenticated. | http://map.geoplatform.gov |

### Optional Fields

| Field | Type | Description| Default |
|---|---|---|---|
|COOKIE_DOMAIN| string | The domain to set for cookie containing the token header. This will determin what domains have access to the token via cookie. | ".geoplatform.gov" |
|REFRESH_DEBOUNCE| int | Milliseconds to delay the request to obtain a new access token. This will allow requests to queue and all return at once when the token has been succesfully refreshed. | 250 |
|PRE_REFRESH_BUFFER| int | Milliseconds before token expires to initiate a pre-expiration refresh request. This is helpful when requests will be passed to another service to prevent token expiration during that request. | 250 |
|REFRESH_LINGER| int | Milliseconds to delay purging refresh token. This is used for slow network traffic or high concurrent request volume. | 250 |
|AUTH_DEBUG| boolean | If true print out debug information from node-gpoauth | false |
|AUTH_DEV_MODE | boolean | Run in development mode. Development mode will change the way that tokens are passed (in cookies). Dev mode is less secure and should not be used in production systems. | false |

### Common Token Cache
The default behavior of the system is to store all refresh tokens locally in memory. This means that only the appliction that originally requested the access and refreh token is able to refresh the access token. If you provide mongoDB setting, the code will use a common TokenCache in mongoDB. This will allow other applictions to use the same tokens and allow a user to stay logged in across multiple applications.

| Field | Type | Description| Default | Example |
|---|---|---|---|---|
|TOKEN_CACHE_HOST | string | The host IP address where the MongoDB is locatied | - | "10.11.12.1" |
|TOKEN_CACHE_USER | string | The username for the Mongo Database. | - | 'MyUser' |
|TOKEN_CACHE_PASS | string | The password for the Mongo user. | - | 'MyPassword' |
|TOKEN_CACHE_PORT | int | The port for MongoDB. | 27017 | 12345 |
|TOKEN_CACHE_AUTHDB | string | The authentication database name for MongoDB (where user data is stored). | 'admin' | 'myAuthDatase' |


<br><br>

## Properties set on "req" object
The JWT and accessToken (encoded JWT) are made avaliable in all authorized node-gpoauth requests. These will not be set on unauthorized requests. The properties are:

|Property|Description|
|---|---|
|req.jwt | The parsed JWT object (See example below) with user related information. |
|req.accessToken| The raw encoded JWT passed back from gpoauth. This accessToken will be required for authentication from any other service requiring a JWT/token for accessing resources.|

<br>

## JWT
Gpoauth passes user data around using JWTs (for more info on JWTs see: https://jwt.io/introduction/). The JWT carries basic user information from gpoauth. A gpoauth JWT will holds the following format:
```javascript
{
  sub: '5a7b3cb5113cb7001d0cd635',            // userId
  name: 'Built-In Admin',                     // full name of user
  email: 'admin@example.com',
  username: 'admin',
  roles: 'admin',
  groups: [                                   // Groups (Roles) a user has/is in
     { _id: '5a7b3cb5113cb7001d0cd63a', name: 'Administrators' },
     { _id: '5a7b3cb5113cb7001d0cd639', name: 'Users' }
  ],
  orgs: [                                     // Users organiztion
    { id: '5a7b3cb5113cb7001d0cd238', name: 'Image Matters, LLC' }
  ],
  scope: [ 'read' ],
  iss: 'https://localhost.local',
  aud: '5a7b3d9e113cb7001d0cd644',
  nonce: 'not implement',
  iat: 1518120742,
  exp: 1518122542
}

```


<br>

## Events
The following events are emitted from the module that allow the hosting Application to respond to IDP events. See the Usage section for an example of seting up an event handler. Only the **unauthorizedRequest** event handler is required to be implemented. See below for a full description of each event.

Avaliable events are:
  - userAuthenticated (optional)
  - unauthorizedRequest (**required**)
  - accessGranted (optional)
  - errorRefreshingAccessToken (optional)
  - accessTokenRevoked (optional)
<br>
<br>


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
>// Determine the endpoints that require a valid JWT
>IDP.on('unauthorizedRequest', (err, req, res, next) => {
>
>  // protect API endpoint from unauthenticated users
>  if(req.originalUrl.match(/api\/.+/)) {
>    res.status(401).send({
>      error: 'Unauthenticated'
>    })
>  } else {
>    // Allow static assets to be served without a valid JWT
>    next();
>  }
>
>})
>```
---
> ## accessGranted (optional)
> This event is called when a user has a valid JWT and are about to be passed on for regular request processing. This event can be used as a kind of catch all middleware for more granular access control based on the user requesting the resource. The JWT can be accessed via req.jwt and user information can then be used to futher restrict access to resources. (See example below).
>
>**NOTE:**
>By default, if this event is not implemented the request will be treated as a regular request.
>
>**Parameters:**
>
>| Name | Type | Description |
>|---|---|---|
>|req | ExpressJS Request | The ExpressJS Requests object. |
>|res | ExpressJS Response | The ExpressJS Response object. |
>|next| Function | ExpressJS middleware next function. This function must be called for the application to continue with the middleware calls. Calling this function will allow a passthrough and Express will continue with serving the request|
>
>
>**Example:**
>```javascript
>IDP.on('accessGranted', (req, res, next) => {
>  // Extract user info from JWT
>  const USER = req.jwt;
>  // Get names of Groups user is in
>  const GROUPS = USER.groups.map(g => g.name)
>
>  // Only allow admins to access resources at the admin endpoints
>  if(GROUPS.indexOf('admin') === -1) {
>    res.status(401).send({
>      err: "Only admin users are able to access this endpoint."
>    })
>  } else {
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


