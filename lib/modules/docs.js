const fs = require('fs')
const util = require('../util')()

const moduleName = 'docs'

module.exports = function (apiOpts = {}) {
    this.config.api = this.getCoreOpts(moduleName, apiOpts, {
        docsEndpoint: apiOpts.docsEndpoint || '/api/docs',
        subdomains: Object.keys(this.config.subdomains),
        ignoreSubdomains: ['index'],
    })

    if (!!this.config.api && fs.existsSync(this.config.folders.controllersFolder)) {
        const swaggerUi = require('swagger-ui-express')

        const ignoreSubdomains = Object.keys(this.core).filter(
            (m) => this.config.api.ignoreSubdomains.indexOf(m) === -1,
        )
        const subdomains = this.config.api.subdomains.filter(
            (s) => ignoreSubdomains.indexOf(s) === -1,
        )
        subdomains.push('api')

        this.app.use(this.config.api.docsEndpoint, swaggerUi.serve)
        this.route(
            this.config.api.docsEndpoint,
            (subdomain, req, res, host, next) => {
                const swaggerSpec = this.getSwaggerSpec(this.config, {
                    servers: util.getServers(
                        this.config,
                        host,
                        req.protocol,
                        subdomain,
                        this.config.apiSecurity && host.indexOf('localhost') === -1,
                        Object.keys(this.core),
                    ),
                })

                return swaggerUi.setup(swaggerSpec)(req, res, next)
            },
            'get',
            this.config.api.secureApiDocs,
            subdomains,
        )

        this.log.info(`📚	serving API documentation at route`, [this.config.api.docsEndpoint])
    }
}
module.exports.module = moduleName
module.exports.description = 'Add OpenApi defined documentation at {hostname}/api/docs by default'
