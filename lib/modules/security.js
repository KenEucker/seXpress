/// Begin with the module name
const moduleName = 'security'

/// Name the module init method which is used in logging
function InitSecurity(initial, securityOpts = {}) {
    this.config.security = this.getCoreOpts(moduleName, securityOpts, initial)

    /// dependencies are scoped to the module itself
    const { merge, getSubdomainPrefix } = this.middlewares.util
    const helmet = require('helmet')
    const cors = require('cors')

    /// TODO: add the nonce creation and validation here for the hooks module

    const setCorsAllowAll = function setCors(res) {
        // CORS headers
        res.header('Access-Control-Allow-Origin', '*') // restrict it to the required domain
        res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,OPTIONS')

        // Set custom headers for CORS
        res.header('Access-Control-Allow-Headers', 'Content-type,Accept,X-Access-Token,X-Key')
    }

    if (!this.config.debug) {
        const corsOpts = merge(
            {
                // origin: true,
                origin: (origin, callback) => {
                    /// Allow all from host
                    if (typeof origin === 'undefined' || origin === 'null')
                        return callback(null, true)

                    /// If origin matches the site base url
                    const baseUrl = this.getBaseUrl(this.config.host, undefined, undefined, false)
                    if (origin === baseUrl) return callback(null, true)

                    /// If the origin is one of our subdomains
                    const originSubdomain = getSubdomainPrefix(this.config, origin)
                    const matchesSubdomain =
                        Object.keys(this.config.subdomains).indexOf(originSubdomain) !== -1
                    if (matchesSubdomain) return callback(null, true)

                    /// Otherwise, reject the cors request
                    this.log.status(`🛡️ rejecting cors request from ${origin}`)
                    return callback(`${origin} Not Allowed`, Object.keys(this.config.subdomains))
                },
                credentials: true,
            },
            this.config.security.cors || {},
        )
        this.app.use((req, res, next) => {
            const subdomain = getSubdomainPrefix(this.config, req)
            /// Allow all api.{host} requests
            if (subdomain !== 'api') return cors(corsOpts)(req, res, next)

            next()
        })
        this.app.options('*', cors())
        this.log.info(`🛡️  basic request security enabled`)
    } else {
        this.app.all(
            '/*',
            this.requestHandler(
                function allowAllHandler(req, res, next) {
                    console.log(`👓`, req.url)
                    setCorsAllowAll(res)
                    return next()
                },
                undefined,
                true,
            ),
        )
        this.log.info(`👓  security disabled, allowing all connections`)
    }

    if (this.config.ssl.enabled) {
        const contentSecurityPolicy = merge(
            {
                directives: {
                    baseUri: [`'none'`],
                    defaultSrc: [`'self'`],
                    objectSrc: [`'none'`],
                    imgSrc: [`'self'`, `*.${this.config.host}`, `${this.config.host}`],
                    fontSrc: [
                        `'self'`,
                        `data:`,
                        `https://fonts.gstatic.com`,
                        `https://fonts.googleapis.com`,
                    ],
                    connectSrc: [
                        `'self'`,
                        `wss://localhost:9856`,
                        `*.${this.config.host}`,
                        `${this.config.host}`,
                    ],
                    scriptSrc: [`'self'`, (req, res) => `'nonce-${res.locals.nonce}'`],
                    styleSrc: [
                        `'self'`,
                        (req, res) => `'nonce-${res.locals.nonce}'`,
                        `https://fonts.googleapis.com`,
                    ],
                },
            },
            this.config.ssl.contentSecurityPolicy || {},
        )
        this.app.use(
            helmet({
                hsts: {
                    maxAge: 5184000,
                    includeSubDomains: true,
                    preload: true,
                },
                contentSecurityPolicy: !this.config.debug ? contentSecurityPolicy : false,
            }),
        )
    }
}

module.exports = InitSecurity
module.exports.module = moduleName
module.exports.description = 'Injects security into protected endpoints'
module.exports.version = '0.0.1'
