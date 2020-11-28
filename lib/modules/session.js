/// Begin with the module name
const moduleName = 'session'

/// Name the module init method which is used in logging
async function InitSession(initial, sessionOpts = {}) {
    /// dependencies are scoped to the module itself
    const express = require('express')
    const passport = require('passport')
    const bodyParser = require('body-parser')
    const cookieSession = require('cookie-session')
    const cookieParser = require('cookie-parser')
    const favicon = require('serve-favicon')
    const { v4: uuid } = require('uuid')
    const { existsSync } = require('fs')
    const { join } = require('path')
    const { merge } = require('../util')(this.config.appRoot)

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

    if (this.config.session.enabled) {
        const cookieOpts = merge(
            {
                name: this.config.name,
                key: this.config.name,
                keys: ['domain', 'maxAge'],
                resave: false,
                saveUninitialized: true,
                secret: this.config.authentication
                    ? this.config.authentication.secret || this.config.name
                    : this.config.name,
                cookie: {
                    domain: `.${this.config.host}`,
                    maxAge: 60 * 60 * 24,
                },
            },
            this.config.session.cookies,
        )

        if (this.config.session.redis.enabled) {
            const redis = require('redis')
            const session = require('express-session')
            const connectRedis = require('connect-redis')

            try {
                /// Start our Redis server
                const RedisServer = require('redis-server')
                const server = new RedisServer(
                    merge(
                        {
                            port: 6379,
                        },
                        this.config.session.redis || {},
                    ),
                )

                await server.open((err) => {
                    if (err) throw err

                    const RedisStore = connectRedis(session)
                    const redisClient = redis.createClient()

                    cookieOpts.genid = cookieOpts.genid
                        ? cookieOpts.genid
                        : (req) => {
                              const newUuid = uuid()
                              console.log({ newUuid })
                              return newUuid
                          }
                    cookieOpts.store = new RedisStore({ client: redisClient })

                    this.app.use(session(cookieOpts))

                    this.log.info(`⛺️ redis storage enabled for sessions`)
                })
            } catch (e) {
                return this.log.error(`redis server failed to start`, e)
            }
        } else {
            this.app.use(cookieParser())
            this.app.use(cookieSession(cookieOpts))
            this.app.set('trust proxy', 1) // trust first proxy

            this.log.info(`🥠 cookies set for domain: ${cookieOpts.domain}`, { cookieOpts })
        }

        /// Add nonces to scripts and other inline resources
        this.app.use((req, res, next) => {
            res.locals.nonce = uuid()
            next()
        })
    }

    if (this.config.host.indexOf('localhost') !== -1) {
        this.app.set('subdomain offset', 1)
    }

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
    this.app.use(bodyParser.json())
    this.app.use(
        bodyParser.urlencoded({
            extended: false,
        }),
    )

    /// Initialize passportjs
    if (this.config.authentication && this.config.authentication.enabled) {
        this.log.debug(`initializing passportjs for the authentication module`, {
            passport: this.config.session.passport,
            session: this.config.session.passport.session,
        })
        this.app.use(passport.initialize(this.config.session.passport))
        this.app.use(passport.session(this.config.session.passport.session))
    }
}

module.exports = InitSession
module.exports.module = moduleName
module.exports.description = `Initializes the app's session`
module.exports.defaults = {
    cookies: {},
    json: {},
    passport: {},
    redis: {
        enabled: false,
    },
}
module.exports.version = '0.0.1'
