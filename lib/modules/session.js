/// Begin with the module name
const moduleName = 'session'

/// Name the module init method which is used in logging
async function InitSession(initial, sessionOpts = {}) {
    /// dependencies are scoped to the module itself
    const express = require('express')
    const cookieSession = require('cookie-session')
    const cookieParser = require('cookie-parser')
    const methodOverride = require('method-override')
    const favicon = require('serve-favicon')
    const { v4: uuid } = require('uuid')
    const { existsSync } = require('fs')
    const { join } = require('path')
    const { merge, getSubdomainPrefix } = this.middlewares.util
    const uest = require('uest')

    this.config.session = this.getCoreOpts(moduleName, sessionOpts, initial)

    /// TODO: loop through here and add subdomain specific favicon overrides
    const defaultFaviconFilename = this.config.favicon || 'favicon.ico'
    const defaultFaviconFilePath = join(this.config.folders.publicFolder, defaultFaviconFilename)
    if (existsSync(defaultFaviconFilePath)) {
        this.log.info(`⭐️ favicon found: ${defaultFaviconFilename}`, defaultFaviconFilePath)
        this.app.use(favicon(defaultFaviconFilePath))
    } else {
        this.log.error('favicon not found', defaultFaviconFilePath)
    }

    /// Add nonces to scripts and other inline resources
    this.app.use((req, res, next) => {
        res.locals.nonce = uuid()
        res.locals.subdomain = getSubdomainPrefix(this.config, req, false)
        res.locals.host = this.getHost()

        next()
    })

    if (this.config.session.enabled) {
        this.app.use(cookieParser())

        if (!this.config.session.disableCookies) {
            const cookieOpts = merge(
                {
                    name: this.config.name,
                    key: this.config.name,
                    keys: ['domain', 'maxAge'],
                    resave: true,
                    sameSite: true,
                    httpOnly: true,
                    saveUninitialized: true,
                    secret: this.config.authentication
                        ? this.config.authentication.secret || this.config.name
                        : this.config.name,
                    cookie: {
                        domain: this.config.host,
                        maxAge: 60 * 60 * 24,
                        httpOnly: true,
                    },
                    rolling: true,
                },
                this.config.session.cookies,
            )

            const sendCookieInfo = (req, res, next) => {
                /// TODO: redirect user to appropriate page, if request is GET
                if (req.method === 'GET' && !this.config.session.redis.enabled) {
                    return res.redirect(`/profile`)
                }

                if (this.isAuthenticated(req)) {
                    return res.json({ session: req.session })
                }

                next()
            }

            this.app.set('trust proxy', 1) // trust first proxy

            this.app.use(methodOverride('X-HTTP-Method-Override'))
            this.app.use(cookieSession(cookieOpts))

            this.app.get('/session', sendCookieInfo)
            this.app.post('/session', sendCookieInfo)

            this.log.info(`🥠 cookies set for domain: ${cookieOpts.cookie.domain}`, { cookieOpts })
        }
    }

    if (this.config.host === 'localhost') {
        this.app.set('subdomain offset', 1)
    }

    /// Set up the ability to passthrough requests to other servers (and/or self)
    this.app.use(uest())

    const jsonOpts = merge(
        {
            spaces: 2,
            urlencoded: true,
        },
        this.config.session.json,
    )
    /// Support JSON-encoded bodies
    this.app.set('json spaces', jsonOpts.spaces)
    if (jsonOpts.urlencoded) {
        this.app.use(express.json())
        this.app.use(
            express.urlencoded({
                extended: true,
            }),
        )
    }
}

module.exports = InitSession
module.exports.module = moduleName
module.exports.description = `Initializes the app's session`
module.exports.defaults = {
    cookies: {},
    json: {},
    redis: {
        enabled: false,
        route: '/session',
    },
}
module.exports.version = '0.0.1'
