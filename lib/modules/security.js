/// Begin with the module name
const moduleName = 'security'

/// Name the module init method which is used in logging
function InitSecurity(initial, securityOpts = {}) {
    this.config.security = this.getCoreOpts(moduleName, securityOpts, initial)

    /// dependencies are scoped to the module itself
    const helmet = require('helmet')
    const enforceSSL = require('express-enforces-ssl')
    const cors = require('cors')
    const util = require('../util')()

    if (this.isSecure()) {
        this.app.enable('trust proxy')

        this.app.use(enforceSSL())
    }

    /// TODO: add the nonce creation and validation here for the hooks module

    const setCorsAllowAll = function setCors(res) {
        // CORS headers
        res.header('Access-Control-Allow-Origin', '*') // restrict it to the required domain
        res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,OPTIONS')

        // Set custom headers for CORS
        res.header('Access-Control-Allow-Headers', 'Content-type,Accept,X-Access-Token,X-Key')
    }

    if (!this.config.debug) {
        const corsOpts = util.merge(
            {
                // origin: true,
                origin: (origin, callback) => {
                    /// Allow all from host
                    if (typeof origin === 'undefined') return callback(null, true)

                    const baseUrl = this.getBaseUrl(this.config.host, undefined, undefined, false)
                    if (origin === baseUrl) return callback(null, true)

                    const originSubdomain = util.getSubdomainPrefix(this.config, origin)
                    const matchesSubdomain =
                        Object.keys(this.config.subdomains).indexOf(originSubdomain) !== -1

                    if (matchesSubdomain) return callback(null, true)

                    /// TODO: check for registered API origin's
                    this.log.status(`🛡️ rejecting cors request from ${origin}`)
                    return callback(`${origin} Not Allowed`, Object.keys(this.config.subdomains))
                },
                credentials: true,
            },
            this.config.security.cors || {},
        )
        this.app.use(cors(corsOpts))
        this.log.info(`🛡️  basic request security enabled`)
    } else {
        this.app.all(
            '/*',
            this.requestHandler(
                function allowAllHandler(subdomain, req, res, host, next) {
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

    if (this.isSecure()) {
        this.app.use(helmet({
			contentSecurityPolicy: {
				directives: {
					defaultSrc: [`'self'`],
					scriptSrc: [`'self'`, (req, res) => `'nonce-${ res.locals.nonce }'`],
					styleSrc: [`'self'`, (req, res) => `'nonce-${ res.locals.nonce }'`]
				}
			}
		  }))
    }
}

module.exports = InitSecurity
module.exports.module = moduleName
module.exports.description = 'Injects security into protected endpoints'
module.exports.version = '0.0.1'
