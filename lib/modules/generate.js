/// Begin with the module name
const moduleName = 'generate'

/// Name the module init method which is used in logging
async function InitGenerate(initial, generateOpts) {
    this.config.generate = this.getCoreOpts(moduleName, generateOpts, initial)
    if (this.config.generate.enabled && this.config.generate.source) {
        return new Promise(async (resolve, reject) => {
            const { existsSync, createReadStream, writeFileSync, createWriteStream } = require('fs')
            const download = require('download')
            const { mkdirp } = require('../util')()
            const { join } = require('path')

            const configFilePath = join(this.config.folders.configFolder, 'config.json')

            /// If the config file is not yet created OR if we need to stay synced
            if (!existsSync(configFilePath) || this.config.generate.sync) {
                this.log.status(
                    `Attempting to load configuration from external source: ${this.config.generate.source}`,
                    { source: this.config.generate.source },
                )
                const unzipper = require('unzipper')
                const tempDir = join(this.config.folders.appFolder, 'temp')
                const tempSourceArchive = join(tempDir, 'source.zip')

                /// Only sync if the source archive doesn't exist
                if (!existsSync(tempSourceArchive)) {
                    const tempSourceOutput = join(tempDir, 'config')
                    const targetAppDir = this.config.folders.appFolder
                    mkdirp.sync(tempDir)
                    mkdirp.sync(tempSourceOutput)

                    writeFileSync(tempSourceArchive, await download(this.config.generate.source))

                    /// WARNING: this will overwrite the local copy of these files. Is the user sure they want to lose any changes to those files?
                    this.log.status(
                        `source downloaded, attempting to unpack config into: ${tempSourceOutput}`,
                    )
                    return createReadStream(tempSourceArchive)
                        .pipe(unzipper.Parse())
                        .on('entry', (entry) => {
                            /// TODO: make these string values configurable defaults
							const outputPath = entry.path.substring(entry.path.indexOf('/') + 1)
                            if (
                                entry.path.indexOf('/config/') !== -1 &&
                                entry.path.endswith('.js')
                            ) {
                                /// copy the config.js file over to the /config folder in the root applicaiton
                                entry.pipe(createWriteStream(join(targetAppDir, 'config', 'config.js')))
                            } else if (
                                entry.path.indexOf('/config/') !== -1 ||
                                entry.path.indexOf('package.json') !== -1
                            ) {
                                /// copy the lib files over to the /lib folder in the root applicaiton
                                entry.pipe(createWriteStream(join(tempDir, outputPath)))
                            } else if (
                                this.config.generate.copyLib &&
                                entry.path.indexOf('/lib/') !== -1
                            ) {
                                /// copy the lib files over to the /lib folder in the root applicaiton
                                entry.pipe(createWriteStream(join(targetAppDir, outputPath)))
                            } else if (
                                this.config.generate.copyControllers &&
                                entry.path.indexOf('/controllers/') !== -1
                            ) {
                                console.log('would copy controllers file', {
                                    path: entry.path,
                                    targetAppDir,
                                })
                                entry.pipe(createWriteStream(join(targetAppDir, outputPath)))
                            } else if (
                                this.config.generate.copyServerFile &&
                                entry.path.endswith('/app.js')
                            ) {
                                /// TODO: this filepath check needs to be more intelligent
                                console.log('would copy server file', {
                                    path: entry.path,
                                    targetAppDir,
                                })
                                entry.pipe(createWriteStream(join(targetAppDir, outputPath)))
                            } else {
                                entry.autodrain()
                            }
                        })
                        .on('close', () => {
                            /// Get the clobfig of the target application
                            const clobfig = require('clobfig')({ relativePath: tempDir })
                            Object.keys(clobfig).forEach((key) => {
                                if (key.startsWith('_')) {
                                    delete clobfig[key]
                                }
                            })

                            /// Save to our config.json the clobfig from the target application
                            writeFileSync(
                                join(this.config.folders.configFolder, 'config.json'),
                                JSON.stringify(clobfig, null, 2),
                            )

                            /// Restart/Reinitialize our app
                            resolve('configuration loaded, restart required')
                        })
                }
            }
            resolve()
        })
    }

    const applicationDefinition = this.config.openApiDefinition
    // const apiDocsTemplateDestination = path.resolve(this.config.folders.templatesFolder, 'docs')
    /// TODO: send to temporary folder to archive into a .zip file that can be downloaded from the api/docs path alongside the swagger.json
    // const swaggerServerCodegen = require('swagger-node-codegen')
    // const swaggerClientCodegen = require('swagger-codegen')
    /// Generate the clientside code to consume the API
    // const clientsideCode = swaggerClientCodegen({
    // 	swagger: this.getSwaggerSpec(this.config),
    // Templates that run per #/definition
    // perDefinition: {
    //   // Substitute for your own handlebars template
    //   // and generate as many as you want.
    //   './path/to/def-template.hbs': {
    // 	target: './target-folder',
    // 	extension: '.js', // Default
    // 	/* Add your own options for templates here */
    //   }
    // },
    // // Templates that run per grouping of
    // // path attributes
    // perPath: {
    //   // Substitute for your own handlebars template
    //   // and generate as many as you want.
    //   './path/to/def-template.hbs': {
    // 	groupBy: 'x-swagger-router-controller',
    // 	target: './controllers',
    // 	extension: '.js', // Default
    // 	operations: ['get', 'put', 'post', 'delete'], // Default
    // 	/* Add your own options for templates here */
    //   }
    // }
    // 	failureHandler: e => console.error(e),
    //   })
    //   console.log({clientsideCode})
    // swaggerServerCodegen.generate({
    // 	swagger: this.getSwaggerSpec(this.config),
    // 	target_dir: apiDocsTemplateDestination,
    // }).then(() => {
    // 	this.log.info(`API template generated`, apiDocsTemplateDestination)
    // }).catch(err => {
    // 	this.log.error(`API template generation failed: ${err.message}`);
    // })
}

module.exports = InitGenerate
module.exports.module = moduleName
module.exports.description = 'Generates a sexpress application out of a single json object'
module.exports.defaults = false
module.exports.version = '0.0.1'
