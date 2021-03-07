/// Begin with the module name
const moduleName = 'docs'

/// Name the module init method which is used in logging
function InitDocs(initial, apiOpts = {}) {
    /// dependencies are scoped to the module itself
    const { merge, getServers } = this.middlewares.util
    const { existsSync } = require('fs')

    /// TODO: document the source code
    // const {document} = require('docco')
    // document(srcDocsOpts)

    apiOpts = this.getCoreOpts(moduleName, merge(this.config.api, apiOpts), initial)

    if (existsSync(this.config.folders.controllersFolder)) {
        // this.registerCoreSubdomain('api')

        const swaggerUi = require('swagger-ui-express')
        const self = this

        const ignoreSubdomains = Object.keys(this.core).filter(
            (m) => apiOpts.ignoreSubdomains.indexOf(m) === -1,
        )
        const subdomains = Object.keys(this.config.subdomains).filter(
            (s) => ignoreSubdomains.indexOf(s) === -1,
        )

        const swaggerUiOpts = {
            // explorer: true,
        }

        this.app.use(apiOpts.docsEndpoint, swaggerUi.serve)
        this.route(
            apiOpts.docsEndpoint,
            function serveApiDocs(req, res, next) {
                const swaggerSpec = self.getSwaggerSpec(
                    self.config,
                    {
                        servers: getServers(
                            self.config,
                            res.locals.host,
                            req.protocol,
                            res.locals.subdomain,
                            apiOpts.secureApiDocs && res.locals.host.indexOf('localhost') === -1,
                            Object.keys(self.core),
                            self.isAuthenticated(req),
                        ),
                    },
                    true,
                )

                return swaggerUi.setup(swaggerSpec, swaggerUiOpts)(req, res, next)
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
module.exports.version = '0.0.1'
