/// Begin with the module name
const moduleName = 'session'

/// Name the module init method which is used in logging
function InitSession(initial, sessionOpts = {}) {
    /// dependencies are scoped to the module itself
    const express = require('express')
    const passport = require('passport')
    const session = require('express-session')
    const bodyParser = require('body-parser')
    const cookieSession = require('cookie-session')
    const cookieParser = require('cookie-parser')
    const favicon = require('serve-favicon')
    const { existsSync } = require('fs')
    const { join } = require('path')
    const { merge } = require('../util')(this.config.appRoot)

    this.config.session = this.getCoreOpts(moduleName, sessionOpts, initial)

    if (this.config.session.enabled) {
        const cookieDomain = `.${this.config.host}`
        const cookieOpts = merge(
            {
                name: this.config.name,
                key: this.config.name,
                keys: ['domain', 'maxAge'],
                secret: this.config.authentication
                    ? this.config.authentication.secret
                    : this.config.name,
                cookie: { domain: cookieDomain, maxAge: 60 * 60 * 24 },
            },
            this.config.session.cookies,
        )

        /// STEP 1: Cookies
        this.app.set('trust proxy', 1) // trust first proxy
        this.app.use(cookieParser())
        this.app.use(cookieSession(cookieOpts))

        this.log.info(`🥠 cookies set for domain: ${cookieDomain}`, { cookieDomain })

        /// STEP 3: Session - Set up request sessions
        // this.app.use(
        //     session({
        //         secret: this.config.session.secret || this.config.name,
        //         resave: this.config.session.resave || true,
        //         saveUninitialized: this.config.session.saveUninitialized || true,
        //     }),
        // )
    }

    if (this.config.host.indexOf('localhost') !== -1) {
        this.app.set('subdomain offset', 1)
    }

    /// STEP 2: JSON and BodyParser
    const jsonOpts = merge(
        {
            spaces: 2,
            urlencoded: true,
        },
        this.config.session.json,
    )

    /// Support JSON-encoded bodies
    this.app.set('json spaces', jsonOpts.spaces)

    /// Support URL-encoded bodies first
    if (jsonOpts.urlencoded) {
        this.app.use(express.json())
        this.app.use(
            express.urlencoded({
                extended: true,
            }),
        )
    }

    /// Use body-parser second
    this.app.use(bodyParser.json())
    this.app.use(
        bodyParser.urlencoded({
            extended: false,
        }),
    )

    /// STEP 4: Passport - Initialize passportjs
    if (this.config.authentication && this.config.authentication.enabled) {
        this.log.debug(`initializing passportjs for the authentication module`, {
            passport: this.config.session.passport,
            session: this.config.session.passport.session,
        })
        this.app.use(passport.initialize(this.config.session.passport))
        this.app.use(passport.session(this.config.session.passport.session))
    }

    /// TODO: loop through here and add subdomain specific favicon overrides
    /// STEP 5: Favicons - Initialize favicons for each of the subdomains
    const defaultFaviconFilename = this.config.favicon || 'favicon.ico'
    const defaultFaviconFilePath = join(this.config.folders.publicFolder, defaultFaviconFilename)
    if (existsSync(defaultFaviconFilePath)) {
        this.log.info(`⭐️ favicon found: ${defaultFaviconFilename}`, defaultFaviconFilePath)
        this.app.use(favicon(defaultFaviconFilePath))
    } else {
        this.log.error('favicon not found', defaultFaviconFilePath)
    }
}

module.exports = InitSession
module.exports.module = moduleName
module.exports.description = `Initializes the app's session`
module.exports.defaults = {
    cookies: {},
    json: {},
    passport: {},
}
module.exports.version = '0.0.1'
