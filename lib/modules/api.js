/// Begin with the module name
const moduleName = 'api'

/// Name the module init method which is used in logging
function InitApi(initial, apiOpts = {}) {
    /// dependencies are scoped to the module itself
    const { copyFileSync, existsSync } = require('fs')
    const util = this.middlewares.util
    const { join } = require('path')

    this.config.api = this.getCoreOpts(
        moduleName,
        util.merge(
            {
                apiFilename: `${this.config.name
                    .trim()
                    .toLocaleLowerCase()
                    .replace(' ', '_')}-api.js`,
            },
            apiOpts,
        ),
        initial,
    )

    // const apiEnabled = typeof this.config.api.enabled && existsSync(this.config.folders.controllersFolder)
    if (this.config.api.enabled && existsSync(this.config.folders.controllersFolder)) {
        const self = this
        this.log.info(`🛥  wrapping /api requests and providing external API`)
        this.registerCoreSubdomain(moduleName)

        const openApiDefinitionFile = join(this.config.folders.controllersFolder, 'swagger.json')
        if (existsSync(openApiDefinitionFile)) {
            this.log.info(`using custom api definition file`, openApiDefinitionFile)
            this.config.openApiDefinitionFile = require(openApiDefinitionFile)
        }

        const apiControllerFile = join(this.config.folders.controllersFolder, 'api', 'index.js')
        const apiControllerExists = existsSync(apiControllerFile)

        let addApiViewOrTemplate =
            typeof this.config.generateApiLandingPage !== 'undefined'
                ? this.config.generateApiLandingPage
                : true

        if (apiControllerExists) {
            const apiController = require(apiControllerFile)
            addApiViewOrTemplate = !apiController.index
        }

        if (addApiViewOrTemplate) {
            /// TODO: make the modules that can accept head requests for this module configurable
            const ignoreSubdomains = Object.keys(this.core).filter(
                (m) => ['index', 'config'].indexOf(m) === -1,
            )
            const subdomains = Object.keys(this.config.subdomains).filter(
                (s) => ignoreSubdomains.indexOf(s) === -1,
            )
            const sendApiTemplate = function sendApiTemplate(req, res) {
                const { host, subdomain } = res.locals
                const data = self.getPublicData(subdomain, host, req.params, res)

                return self.renderViewOrTemplate('api', data, res)
            }

            this.route('/', sendApiTemplate, 'get', undefined, ['api'])
            this.route('/api', sendApiTemplate, 'get', false, subdomains)
        }

        this.route('/api/swagger.json', function getApiSpec(req, res) {
            const { host, subdomain } = res.locals
            const swaggerSpec = self.getSwaggerSpec(
                self.config,
                {
                    servers: util.getServers(
                        self.config,
                        host,
                        req.protocol,
                        subdomain,
                        self.config.authentication.enabled && host === 'localhost',
                        Object.keys(self.core),
                        self.isAuthenticated(req),
                    ),
                },
                true,
            )

            return res.json(swaggerSpec)
        })

        /// Copy the swagger-client dist to our templates/base folder
        const swaggerClientJsFilePath = join(
            process.cwd(),
            'node_modules',
            'swagger-client',
            'dist',
        )

        if (existsSync(swaggerClientJsFilePath)) {
            const minifiedFile = 'swagger-client.browser.min.js'
            const mapFile = `${minifiedFile}.map`
            const minifiedFilePath = join(swaggerClientJsFilePath, minifiedFile)
            const mapFilePath = join(swaggerClientJsFilePath, mapFile)
            const destinationFolder = join(this.config.folders.publicFolder, 'js')

            if (existsSync(minifiedFilePath) && existsSync(mapFilePath)) {
                const destMinifiedFile = this.config.api.apiFilename
                /// The map file must be named the to match the original filename
                const destMapFile = mapFile

                util.mkdirp.sync(destinationFolder)
                copyFileSync(minifiedFilePath, join(destinationFolder, destMinifiedFile))
                copyFileSync(mapFilePath, join(destinationFolder, destMapFile))

                this.log.info(`🚁 copied the swagger-client dist to our templates/base folder`, {
                    destinationFolder,
                    minifiedFile,
                    mapFile,
                })
            } else {
                this.log.info(`❓ the swagger-client package dist files could not be found`, {
                    swaggerClientJsFilePath,
                    minifiedFile,
                    mapFile,
                })
            }
        } else {
            this.log.info(`❓ the swagger-client package could not be found`, {
                swaggerClientJsFilePath,
            })
        }
    } else {
        this.config.api.enabled = false
    }
}

module.exports = InitApi
module.exports.module = moduleName
module.exports.description = 'Adds the api routes at hostname/api'
module.exports.version = '0.0.1'
