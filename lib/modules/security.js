const helmet = require('helmet')
const enforceSSL = require('express-enforces-ssl')
const cors = require('cors')

function InitSecurity(initial, securityOpts = {}) {
    this.config.security = this.getCoreOpts(moduleName, securityOpts, initial)

    if (this.isSecure()) {
        this.app.enable('trust proxy')

        // this.app.use(helmet())
        this.app.use(enforceSSL())
    }

    /// TODO: add the nonce creation and validation here for the hooks module

    const setCors = function setCors(res) {
        // CORS headers
        res.header('Access-Control-Allow-Origin', '*') // restrict it to the required domain
        res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,OPTIONS')

        // Set custom headers for CORS
        res.header('Access-Control-Allow-Headers', 'Content-type,Accept,X-Access-Token,X-Key')
    }

    if (!this.config.debug) {
        const self = this
        this.app.all(
            '*',
            this.requestHandler(
                function securityHandler(subdomain, req, res, host, next) {
                    setCors(res)

                    if (req.method == 'OPTIONS') {
                        self.log.error('failed security check!', { subdomain, host, url: req.url })
                        res.status(403).end()
                    } else {
                        // console.log(`👀`, req.url)
                        next()
                    }
                },
                undefined,
                !this.config.debug,
            ),
        )

        // this.app.use(cors(util.merge({
        // 	origin: true,
        // }, this.config.cors || {})))
        this.log.info(`🛡️  basic request security enabled`)
    } else {
        this.app.all(
            '/*',
            this.requestHandler(
                function allowAllHandler(subdomain, req, res, host, next) {
                    console.log(`👓`, req.url)
                    setCors(res)
                    return next()
                },
                undefined,
                true,
            ),
        )
        this.log.info(`👓  security disabled, allowing all connections`)
    }
}

module.exports = InitSecurity
module.exports.module = 'security'
module.exports.description = 'Injects security into protected endpoints'
module.exports.version = "0.0.1"
