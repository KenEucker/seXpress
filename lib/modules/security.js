const helmet = require('helmet')
const enforceSSL = require('express-enforces-ssl')

module.exports = function () {
    if (this.isSecure()) {
        this.app.enable('trust proxy')

        // this.app.use(helmet())
        this.app.use(enforceSSL())
    }

    if (!this.config.debug) {
        const self = this
        this.app.all(
            '/*',
            this.requestHandler(
                function securityHandler(subdomain, req, res, host, next) {
                    // CORS headers
                    res.header('Access-Control-Allow-Origin', '*') // restrict it to the required domain
                    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,OPTIONS')

                    // Set custom headers for CORS
                    res.header(
                        'Access-Control-Allow-Headers',
                        'Content-type,Accept,X-Access-Token,X-Key',
                    )

                    if (req.method == 'OPTIONS') {
                        self.log.error('failed security check!', { subdomain, host, url: req.url })
                        res.status(403).end()
                    } else {
                        next()
                    }
                },
                undefined,
                true,
            ),
        )
    }

    this.log.info('basic request security enabled')
}
module.exports.module = 'security'
module.exports.description = 'Injects security into protected endpoints'
