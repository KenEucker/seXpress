const util = require('../util')()

module.exports = function (apiOpts = {}) {
    if (this.config.api.enabled) {
        const swaggerUi = require('swagger-ui-express')
        apiOpts = util.merge(
            apiOpts,
            util.merge(
                {
                    docsEndpoint: this.config.api.docsEndpoint || '/api/docs',
                    subdomains: Object.keys(this.config.subdomains),
                    ignoreSubdomains: ['index'],
                },
                this.config.api,
            ),
        )

        const ignoreSubdomains = Object.keys(this.core).filter(
            (m) => apiOpts.ignoreSubdomains.indexOf(m) === -1,
        )
        const subdomains = apiOpts.subdomains.filter((s) => ignoreSubdomains.indexOf(s) === -1)
        subdomains.push('api')

        this.app.use(apiOpts.docsEndpoint, swaggerUi.serve)
        this.route(
            apiOpts.docsEndpoint,
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
            apiOpts.secureApiDocs,
            subdomains,
        )

        this.config.api.docsEndpoint = apiOpts.docsEndpoint
        this.config.api.subdomains = apiOpts.subdomains
        this.config.api.ignoreSubdomains = apiOpts.ignoreSubdomains

        this.log.info(`Running API documentation at route`, [apiOpts.docsEndpoint])
    }
}
module.exports.module = 'docs'
module.exports.description = 'Add OpenApi defined documentation at {hostname}/api/docs by default'
