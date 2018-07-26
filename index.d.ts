// Types in node-gpoauth

// Roles in IDP (gpoauth)
type IDPRole = admin
             | staff
             | user

// Configuration for node-gpoauth
type gpoauthConfig = {
    IDP_BASE_URL: string
    APP_ID: string
    APP_SECRET: string
    APP_BASE_URL: string
    REFRESH_DEBOUNCE?: number
    PRE_REFRESH_BUFFER?: number
    AUTH_DEBUG?: boolean
}

// JWT from gpoauth
type JWT = {
    sub : string
    name: string
    email: string
    username: string
    roles: IDPRole
    groups: [{ _id: string, name: string }]
    orgs: [{ _id: string, name: string }]
    scope: [string]
    iss: string
    aud: string
    nonce: string
    iat: number
    exp: number
  }

// UserProfile from gpoauth
type userProfile = {
    _id: string
    modificationDate: string
    creationDate: string
    username: string
    title: string
    firstName: string
    lastName: string
    middleName: string
    email: string
    appRole: IDPRole
    __v: number
    lastLogin: string
    resetHash: null
    resetExp: null
    appSettings: [object]
    auditLog: [undefined]
    lockoutCount: number
    lockedOut: booelan
}
