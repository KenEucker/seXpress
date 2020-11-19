const fs = require('fs')
const path = require('path')
const util = require('../util')()

module.exports = function () {
    if (fs.existsSync(this.config.controllersFolder)) {
        const openApiDefinitionFile = path.join(this.config.controllersFolder, 'swagger.json')
        if (fs.existsSync(openApiDefinitionFile)) {
            this.log.info(`using custom api definition file`, openApiDefinitionFile)
            this.config.openApiDefinitionFile = require(openApiDefinitionFile)
        }
        const apiControllerFile = path.join(this.config.controllersFolder, 'api', 'index.js')
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
            this.route('/api', (subdomain, req, res, host) => {
                return this.renderViewOrTemplate('api', req.params, res)
            })
        }
        this.route('/api/swagger.json', (subdomain, req, res, host) => {
            const swaggerSpec = this.getSwaggerSpec(this.config, {
                servers: util.getServers(
                    this.config,
                    host,
                    req.protocol,
                    subdomain,
                    this.config.security.enabled && host.indexOf('localhost') === -1,
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
            const destinationFolder = path.join(this.config.publicFolder, 'js')

            if (fs.existsSync(minifiedFilePath) && fs.existsSync(mapFilePath)) {
                const destMinifiedFile = `${this.config.appName}-api.js`
                const destMapFile = `${destMinifiedFile}.map`

                util.mkdirp.sync(destinationFolder)
                fs.copyFileSync(minifiedFilePath, path.join(destinationFolder, destMinifiedFile))
                fs.copyFileSync(mapFilePath, path.join(destinationFolder, destMapFile))

                this.log.debug(`Copied the swagger-client dist to our templates/base folder`, {
                    destinationFolder,
                    minifiedFile,
                    mapFile,
                })
            } else {
                this.log.debug(`The swagger-client package dist files could not be found`, {
                    swaggerClientJsFilePath,
                    minifiedFile,
                    mapFile,
                })
            }
        } else {
            this.log.info(`The swagger-client package could not be found`, {
                swaggerClientJsFilePath,
            })
        }
    }
}
module.exports.module = 'api'
module.exports.description = 'Adds the api routes at hostname/api'
