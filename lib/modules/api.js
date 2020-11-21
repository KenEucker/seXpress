const fs = require('fs')
const path = require('path')
const util = require('../util')()

const moduleName = 'api'

module.exports = function (apiOpts = {}) {
    this.config.api = this.getCoreOpts(moduleName, apiOpts, {
        enabled: true,
    })

    if (this.config.api.enabled && fs.existsSync(this.config.folders.controllersFolder)) {
        const openApiDefinitionFile = path.join(
            this.config.folders.controllersFolder,
            'swagger.json',
        )
        if (fs.existsSync(openApiDefinitionFile)) {
            this.log.info(`using custom api definition file`, openApiDefinitionFile)
            this.config.openApiDefinitionFile = require(openApiDefinitionFile)
        }
        const apiControllerFile = path.join(
            this.config.folders.controllersFolder,
            'api',
            'index.js',
        )
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
            const swaggerSpec = this.getSwaggerSpec(this.config, {
                servers: util.getServers(
                    this.config,
                    host,
                    req.protocol,
                    subdomain,
                    this.config.authentication.enabled && host.indexOf('localhost') === -1,
                    Object.keys(this.core),
                ),
            })

            return res.json(swaggerSpec)
        })

        /// Copy the swagger-client dist to our templates/base folder
        const swaggerClientJsFilePath = path.join(
            __dirname,
            '..',
            '..',
            'node_modules',
            'swagger-client',
            'dist',
        )

        if (fs.existsSync(swaggerClientJsFilePath)) {
            const minifiedFile = 'swagger-client.browser.min.js'
            const mapFile = `${minifiedFile}.map`
            const minifiedFilePath = path.join(swaggerClientJsFilePath, minifiedFile)
            const mapFilePath = path.join(swaggerClientJsFilePath, mapFile)
            const destinationFolder = path.join(this.config.folders.publicFolder, 'js')

            if (fs.existsSync(minifiedFilePath) && fs.existsSync(mapFilePath)) {
                const destMinifiedFile = `${this.config.appName
                    .trim()
                    .toLocaleLowerCase()
                    .replace(' ', '_')}-api.js`
                const destMapFile = `${destMinifiedFile}.map`

                util.mkdirp.sync(destinationFolder)
                fs.copyFileSync(minifiedFilePath, path.join(destinationFolder, destMinifiedFile))
                fs.copyFileSync(mapFilePath, path.join(destinationFolder, destMapFile))

                this.log.debug(`🚁 copied the swagger-client dist to our templates/base folder`, {
                    destinationFolder,
                    minifiedFile,
                    mapFile,
                })
            } else {
                this.log.debug(`❓ the swagger-client package dist files could not be found`, {
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
module.exports.module = moduleName
module.exports.description = 'Adds the api routes at hostname/api'
