# node-gpoauth

A NodeJS module used for automating the link to gpoauth's OAuth2 IDP for a NodeJS applictaion.

## Overview
Node-gpoauth is a standardized node module that can be loading into any NodeJS appliction.
Node-gpoauth does the following things:
- Automatically direct user to IDP for authentication
- Setup endpoints on your application for redirecting users for Authentication and communicating with gpoauth IDP
- Fetch Bearer token (JWT) and pass it to the browser (user)
- Unpack and make JWT data avaliable per request
- Emit important authentication events to hosting application

The node-gpoauth moduel will setup up a few api routes for your application. These routes are:

| Endpoint | Description |
|---|---|
|/login | Endpoint that will re-direct user to IDP for authentication. |
|/authtoken | Endopint that will handle Grant Code exchange from IDP. |

<br><br>

## Usage
Import node-gpoauth directly from github using the following in package.json:
> npm install https://github.com/GeoPlatform/node-gpoauth  

<br>

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
IDP.on('userAuthenticated', user => {
  // Register/link IDP user with application user
  user === {
    "_id": "KILTjRrzRhitJY5CRW56s9owDEMtYCldAj4IE6NxwN",
    "modificationDate": "2017-10-27T13:47:42.207Z",
    "creationDate": "2017-07-24T19:13:45.730Z",
    "username": "user",
    "title": "",
    "firstName": "Application",
    "lastName": "User",
    "middleName": "",
    "email": "user@email.com",
    "appRole": "admin",
    "__v": 0,
    "lastLogin": "2017-10-27T13:47:42.205Z",
    "resetHash": null,
    "resetExp": null,
    "appSettings": [],
    "auditLog": [],
    "lockoutCount": 7,
    "lockedOut": false
  }
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
---
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

<br><br>

## Events
---
The following events are emitted from the module that allow the hosting Application to respond to IDP events. See the Usage section for an example of seting up an event handler. Avaliable events are listed below

>### userAuthenticated
>Event that is fired when a user is authenticated to IDP through your application. This event is useful for creating a user in your system (or linking an existing user in your system) with an IDP user.  
>
>**Parameters:**
>
>| Name | Type | Description |
>|---|---|---|
>|user | User | The user passed back from the IDP service (See example above for Object properties) |
