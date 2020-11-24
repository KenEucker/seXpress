const fs = require('fs')

const moduleName = 'docs'

function InitDocs(initial, apiOpts = {}) {
    const util = require('../util')(this.config.appRoot)
    apiOpts = this.getCoreOpts(moduleName, util.merge(this.config.api, apiOpts), initial)

    if (fs.existsSync(this.config.folders.controllersFolder)) {
        const swaggerUi = require('swagger-ui-express')

        const ignoreSubdomains = Object.keys(this.core).filter(
            (m) => apiOpts.ignoreSubdomains.indexOf(m) === -1,
        )
        const subdomains = Object.keys(this.config.subdomains).filter(
            (s) => ignoreSubdomains.indexOf(s) === -1,
        )
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
                        apiOpts.secureApiDocs && host.indexOf('localhost') === -1,
                        Object.keys(this.core),
                    ),
                })

                return swaggerUi.setup(swaggerSpec)(req, res, next)
            },
            'get',
            apiOpts.secureApiDocs,
            subdomains,
        )

        this.log.info(
            `📚 serving generated API documentation${apiOpts.secureApiDocs ? ` *secure*` : ''}`,
            [apiOpts.docsEndpoint],
        )
    }
}
module.exports = InitDocs
module.exports.module = moduleName
module.exports.description = 'Add OpenApi defined documentation at {hostname}/api/docs by default'
module.exports.defaults = {
    secureApiDocs: true,
    docsEndpoint: '/api/docs',
    ignoreSubdomains: ['index'],
}
module.exports.version = "0.0.1"
