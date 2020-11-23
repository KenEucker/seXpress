const fs = require('fs')
const path = require('path')
const express = require('express')
const passport = require('passport')
const session = require('express-session')
const bodyParser = require('body-parser')
const cookieSession = require('cookie-session')
const cookieParser = require('cookie-parser')
const favicon = require('serve-favicon')

const moduleName = 'session'

module.exports = function InitSession(initial, sessionOpts = {}) {
	this.config.session = this.getCoreOpts(moduleName, sessionOpts, initial)
	const util = require('../util')(this.config.appRoot)
	
	if (this.config.session.enabled) {
		const cookieOpts = cookieSession(
			util.merge(
				{
					name: this.config.name,
					key: this.config.name,
					keys: ['domain', 'maxAge'],
					secret: this.config.authentication
						? this.config.authentication.secret
						: this.config.name,
					cookie: { domain: this.config.host, maxAge: 60 * 60 * 24 },
				},
				this.config.session.cookies,
			),
		)

		/// STEP 1: Cookies
		this.app.set('trust proxy', 1) // trust first proxy
		this.app.use(cookieParser())
		this.app.use(cookieOpts)

		this.log.debug(`🥠 cookies set`, { domain: this.config.host })
	}

    if (this.config.host.indexOf('localhost') !== -1) {
        this.app.set('subdomain offset', 1)
    }

    /// STEP 2: JSON and BodyParser
    const jsonOpts = util.merge(
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

    /// STEP 3: Session - Set up request sessions
    this.app.use(
        session({
            secret: this.config.session.secret || this.config.name,
            resave: this.config.session.resave || true,
            saveUninitialized: this.config.session.saveUninitialized || true,
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

    const faviconFilename = this.config.favicon || 'favicon.ico'
    const faviconFilePath = path.join(this.config.folders.publicFolder, faviconFilename)
    if (fs.existsSync(faviconFilePath)) {
        this.log.info(`⭐️ favicon found: ${faviconFilename}`, faviconFilePath)
        this.app.use(favicon(faviconFilePath))
    } else {
        this.log.error('favicon not found', faviconFilePath)
    }
}
module.exports.module = moduleName
module.exports.description = `Initializes the app's session`
module.exports.defaults = {
	cookies: {},
	json: {},
	passport: {},
}
