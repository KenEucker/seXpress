const util = require('../util')()

module.exports = function () {
    const swaggerUi = require('swagger-ui-express')
    const apiDocsEndpoint = '/api/docs'

    this.app.use(apiDocsEndpoint, swaggerUi.serve)
    this.route(
        apiDocsEndpoint,
        (subdomain, req, res, host, next) => {
            const swaggerSpec = this.getSwaggerSpec(this.config, {
                servers: util.getServers(
                    this.config,
                    host,
                    req.protocol,
                    subdomain,
                    this.config.apiSecurity && host.indexOf('localhost') === -1,
                ),
            })

            return swaggerUi.setup(swaggerSpec)(req, res, next)
        },
        'get',
        this.config.secureApiDocs,
    )

    this.log.info(`Running API documentation at route`, [apiDocsEndpoint])
}
module.exports.module = 'docs'
module.exports.description = 'Add OpenApi defined documentation at hostname/api/docs'
