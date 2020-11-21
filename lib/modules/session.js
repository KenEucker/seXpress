const fs = require('fs')
const path = require('path')
const express = require('express')
const passport = require('passport')
const session = require('express-session')
const bodyParser = require('body-parser')
const cookieSession = require('cookie-session')
const cookieParser = require('cookie-parser')
const favicon = require('serve-favicon')
const util = require('../util')()

module.exports = function (sessionOpts = {}) {
    const domain = `.${this.config.host}`
    this.config.session = util.merge(
        this.config.session || {
            cookies: {},
            json: {},
            passport: {},
        },
        sessionOpts,
    )
    const cookieOpts = cookieSession(
        util.merge(
            {
                name: this.config.appName,
                key: this.config.appName,
                keys: ['domain', 'maxAge'],
                secret: this.config.authentication
                    ? this.config.authentication.secret
                    : this.config.appName,
                cookie: { domain, maxAge: 60 * 60 * 24 },
            },
            this.config.session.cookies,
        ),
    )

    this.app.set('trust proxy', 1) // trust first proxy
    this.app.use(cookieParser())
    this.app.use(cookieOpts)

    this.log.debug(`🥠 cookies set`, { domain })

    if (this.config.host.indexOf('localhost') !== -1) {
        this.app.set('subdomain offset', 1)
    }

    const jsonOpts = util.merge(
        {
            spaces: 2,
            urlencoded: true,
        },
        this.config.session.json,
    )

    /// Support JSON-encoded bodies
    this.app.set('json spaces', jsonOpts.spaces)

    /// Use body-parser
    this.app.use(bodyParser.json())
    this.app.use(
        bodyParser.urlencoded({
            extended: false,
        }),
    )

    /// Support URL-encoded bodies
    if (jsonOpts.urlencoded) {
        this.app.use(express.json())
        this.app.use(
            express.urlencoded({
                extended: true,
            }),
        )
    }

    /// Set up request sessions
    this.app.use(
        session({
            secret: this.config.session.secret || this.config.appName,
            resave: this.config.session.resave || true,
            saveUninitialized: this.config.session.saveUninitialized || true,
        }),
    )

    /// Initialize passportjs
    this.app.use(passport.initialize(this.config.session.passport))
    this.app.use(passport.session(this.config.session.passport.session))

    const faviconFilename = this.config.favicon || 'favicon.ico'
    const faviconFilePath = path.join(this.config.folders.publicFolder, faviconFilename)
    if (fs.existsSync(faviconFilePath)) {
        this.log.info(`⭐️ favicon found: ${faviconFilename}`, faviconFilePath)
        this.app.use(favicon(faviconFilePath))
    } else {
        this.log.error('favicon not found', faviconFilePath)
    }
}
module.exports.module = 'session'
module.exports.description = `Initializes the app's session`
