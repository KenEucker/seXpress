/// Begin with the module name
const moduleName = 'api'

/// Name the module init method which is used in logging
function InitApi(initial, apiOpts = {}) {
    /// dependencies are scoped to the module itself
    const fs = require('fs')
    const util = require('../util')(this.config.appRoot)
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

    // const apiEnabled = typeof this.config.api.enabled && fs.existsSync(this.config.folders.controllersFolder)
    if (this.config.api.enabled && fs.existsSync(this.config.folders.controllersFolder)) {
        this.log.info(`🛥  wrapping /api requests and providing external API`)
        const openApiDefinitionFile = join(this.config.folders.controllersFolder, 'swagger.json')
        if (fs.existsSync(openApiDefinitionFile)) {
            this.log.info(`using custom api definition file`, openApiDefinitionFile)
            this.config.openApiDefinitionFile = require(openApiDefinitionFile)
        }
        const apiControllerFile = join(this.config.folders.controllersFolder, 'api', 'index.js')
        const apiControllerExists = fs.existsSync(apiControllerFile)

        let addApiViewOrTemplate =
            typeof this.config.generateApiLandingPage !== 'undefined'
                ? this.config.generateApiLandingPage
                : true

        if (apiControllerExists) {
            const apiController = require(apiControllerFile)
            addApiViewOrTemplate = !apiController.index
        }

        if (addApiViewOrTemplate) {
            const ignoreSubdomains = Object.keys(this.core).filter(
                (m) => ['index'].indexOf(m) === -1,
            )
            const subdomains = Object.keys(this.config.subdomains).filter(
                (s) => ignoreSubdomains.indexOf(s) === -1,
            )
            const sendApiTemplate = (subdomain, req, res, host) => {
                return this.renderViewOrTemplate('api', req.params, res)
            }

            this.route('/', sendApiTemplate, 'get', false, ['api'])
            this.route('/api', sendApiTemplate, 'get', false, subdomains)
        }

        this.route('/api/swagger.json', (subdomain, req, res, host) => {
            const swaggerSpec = this.getSwaggerSpec(
                this.config,
                {
                    servers: util.getServers(
                        this.config,
                        host,
                        req.protocol,
                        subdomain,
                        this.config.authentication.enabled && host.indexOf('localhost') === -1,
                        Object.keys(this.core),
                        req.isAuthenticated(),
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

        if (fs.existsSync(swaggerClientJsFilePath)) {
            const minifiedFile = 'swagger-client.browser.min.js'
            const mapFile = `${minifiedFile}.map`
            const minifiedFilePath = join(swaggerClientJsFilePath, minifiedFile)
            const mapFilePath = join(swaggerClientJsFilePath, mapFile)
            const destinationFolder = join(this.config.folders.publicFolder, 'js')

            if (fs.existsSync(minifiedFilePath) && fs.existsSync(mapFilePath)) {
                const destMinifiedFile = this.config.api.apiFilename
                const destMapFile = `${destMinifiedFile}.map`

                util.mkdirp.sync(destinationFolder)
                fs.copyFileSync(minifiedFilePath, join(destinationFolder, destMinifiedFile))
                fs.copyFileSync(mapFilePath, join(destinationFolder, destMapFile))

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
