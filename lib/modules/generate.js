/// Begin with the module name
const moduleName = 'generate'

/// Name the module init method which is used in logging
async function InitGenerate(initial, generateOpts) {
    this.config.generate = this.getCoreOpts(moduleName, generateOpts, initial)
    if (this.config.generate.enabled && this.config.generate.source) {
        return new Promise(async (resolve, reject) => {
            const { mkdirp } = this.middlewares.util
            const { existsSync, createReadStream, writeFileSync, createWriteStream } = require('fs')
            const download = require('download')
            const { join } = require('path')
            const { copyFileSync } = require('fs')

            const configFilePath = join(this.config.folders.configFolder, 'config.json')
            mkdirp.sync(this.config.folders.configFolder)

            /// If the config file is not yet created OR if we need to stay synced
            if (!existsSync(configFilePath) || this.config.generate.sync) {
                const tempDir = join(this.config.folders.appFolder, 'temp')
                const tempSourceArchive = join(tempDir, 'source.zip')
                const tempTemplateArchive = join(tempDir, 'templates.zip')
                const unzipper = require('unzipper')
                const tempSourceOutput = join(tempDir, 'config')
                const targetAppDir = this.config.folders.appFolder

                try {
                    mkdirp.sync(tempDir)
                    mkdirp.sync(tempSourceOutput)

                    /// Only download the source if it doesn't already exist
                    if (!existsSync(tempSourceArchive)) {
                        const freshSourceUrl = `${this.config.generate.source}${
                            this.config.generate.source.indexOf('?') === -1 ? '?' : '&'
                        }time=${new Date().getTime()}`
                        this.log.status(
                            `Attempting to download sources external: ${this.config.generate.source}`,
                            { source: freshSourceUrl, tempDir, tempSourceArchive },
                        )
                        writeFileSync(tempSourceArchive, await download(freshSourceUrl))
                    }

                    if (this.config.generate.templatesSource) {
                        const freshTemplatesSourceUrl = `${this.config.generate.templatesSource}${
                            this.config.generate.templatesSource.indexOf('?') === -1 ? '?' : '&'
                        }time=${new Date().getTime()}`
                        this.log.status(
                            `Attempting to download templates from external: ${this.config.generate.templatesSource}`,
                            { source: freshTemplatesSourceUrl, tempDir, tempSourceArchive },
                        )
                        writeFileSync(tempTemplateArchive, await download(freshTemplatesSourceUrl))
                    }

                    const copyFileFromArchive = (entry, destination, filePath = '') => {
                        filePath = join(destination, filePath)

                        if (entry.type === 'Directory') {
                            mkdirp.sync(filePath)
                        } else {
                            entry.pipe(createWriteStream(filePath))
                            return true
                        }

                        return false
                    }

                    const extractConfigFiles = (entry, targetAppDir, copyConfig = true) => {
                        /// TODO: make these string values configurable defaults
                        const outputPath = entry.path.substring(entry.path.indexOf('/') + 1)
                        const targetDir = join(targetAppDir, 'temp')
                        let processed = false

                        /// TODO: make this more intelling with a map of files to copy from source
                        if (
                            this.config.generate.copyConfigJs &&
                            outputPath.indexOf('config/config.js') === 0 &&
                            outputPath.indexOf('.json') === -1
                        ) {
                            /// copy the config.js file over to the /config folder in the root applicaiton
                            processed = copyFileFromArchive(
                                entry,
                                join(targetAppDir, 'config'),
                                'config.js',
                            )
                        } else if (
                            entry.type !== 'Directory' &&
                            copyConfig &&
                            (outputPath.indexOf('config/') === 0 ||
                                outputPath.indexOf('package.json') === 0)
                        ) {
                            /// copy the lib files over to the /lib folder in the root applicaiton
                            processed = copyFileFromArchive(entry, targetDir, outputPath)
                        } else if (
                            this.config.generate.copyLib &&
                            outputPath.indexOf('lib/') === 0
                        ) {
                            /// copy the lib files over to the /lib folder in the root applicaiton
                            processed = copyFileFromArchive(entry, targetAppDir, outputPath)
                        } else if (
                            this.config.generate.copyControllers &&
                            outputPath.indexOf('controllers/') === 0
                        ) {
                            /// copy the lib files over to the /lib folder in the root applicaiton
                            processed = copyFileFromArchive(entry, targetAppDir, outputPath)
                        } else if (
                            this.config.generate.copySource &&
                            outputPath.indexOf('src/') === 0
                        ) {
                            /// copy the src files over to the /controllers folder in the root applicaiton
                            processed = copyFileFromArchive(entry, targetAppDir, outputPath)
                        } else if (
                            this.config.generate.copyServerFile &&
                            outputPath.indexOf('app.js') === 0
                        ) {
                            /// TODO: this filepath check needs to be more intelligent
                            processed = copyFileFromArchive(entry, targetAppDir, outputPath)
                        } else {
                            return false
                        }

                        return processed
                    }

                    const generateClobfigJson = (targetDir) => {
                        const removeFields = [
                            'AppRoot',
                            'appRootPath',
                            'configFilePath',
                            'relativePath',
                            'configFolderName',
                            'generate',
                        ]
                        const configDefaults = this.defaults()
                        configDefaults.relativePath = targetDir

                        /// Get the clobfig of the target application
                        const clobfig = require('clobfig')(configDefaults)
                        Object.keys(clobfig).forEach((key) => {
                            if (key.startsWith('_') || removeFields.indexOf(key) !== -1) {
                                delete clobfig[key]
                            }
                        })

                        /// Save to our config.json the clobfig from the target application
                        writeFileSync(
                            join(this.config.folders.configFolder, 'config.json'),
                            JSON.stringify(clobfig, null, `\t`),
                        )

                        /// Import the dependencies from the source
                        if (this.config.generate.importDependencies) {
                            const sourcePackageJsonPath = join(tempDir, 'package.json')
                            const thisPackageJsonPath = join(targetAppDir, 'package.json')

                            if (
                                existsSync(sourcePackageJsonPath) &&
                                existsSync(thisPackageJsonPath)
                            ) {
                                const packageJson = require(thisPackageJsonPath)
                                const sourcePackageJson = require(sourcePackageJsonPath)
                                packageJson.dependencies = packageJson.dependencies || {}

                                Object.keys(sourcePackageJson.dependencies).forEach(
                                    (dependencyName) => {
                                        /// Dependecies should be locked here.
                                        const dependencyVersion = sourcePackageJson.dependencies[
                                            dependencyName
                                        ].replace('^', '')

                                        if (!packageJson.dependencies[dependencyName]) {
                                            packageJson.dependencies[
                                                dependencyName
                                            ] = dependencyVersion
                                        } else if (
                                            !this.config.generate.keepExistingDepdencyVersions
                                        ) {
                                            /// defaulting to the opposite of a flag that begins in an undefined state
                                            packageJson.dependencies[
                                                dependencyName
                                            ] = dependencyVersion
                                        }
                                    },
                                )

                                writeFileSync(
                                    thisPackageJsonPath,
                                    JSON.stringify(packageJson, null, `\t`),
                                )
                            }
                        }
                    }

                    const tempTemplateArchiveExists = existsSync(tempTemplateArchive)
                    const tempSourceArchiveExists = existsSync(tempSourceArchive)

                    if (tempSourceArchiveExists) {
                        /// WARNING: this will overwrite the local copy of these files. Is the user sure they want to lose any changes to those files?
                        this.log.status(
                            `source downloaded, attempting to unpack config into: ${tempSourceOutput}`,
                            tempSourceArchive,
                        )
                        const sourceArchiveFiles = createReadStream(tempSourceArchive)
                            .pipe(unzipper.Parse({ forceStream: true }))
                            .on('close', () => {
                                if (
                                    !tempTemplateArchiveExists ||
                                    !this.config.generate.copyTemplateConfig
                                ) {
                                    return generateClobfigJson(tempDir)
                                }
                            })

                        for await (const entry of sourceArchiveFiles) {
                            if (
                                !extractConfigFiles(
                                    entry,
                                    targetAppDir,
                                    this.config.generate.copySourceConfig,
                                )
                            ) {
                                entry.autodrain()
                            } else {
                                this.log.status(`file unpacked: ${entry.path}`)
                            }
                        }
                    }

                    if (tempTemplateArchiveExists) {
                        /// WARNING: this will overwrite the local copy of these files. Is the user sure they want to lose any changes to those files?
                        this.log.status(
                            `templates downloaded, attempting to unpack templates and public folder into root: ${targetAppDir}`,
                            tempTemplateArchive,
                        )
                        const tempArchiveFiles = createReadStream(tempTemplateArchive).pipe(
                            unzipper.Parse({ forceStream: true }),
                        )

                        for await (const entry of tempArchiveFiles) {
                            /// TODO: make these string values configurable defaults
                            const outputPath = entry.path.substring(entry.path.indexOf('/') + 1)
                            if (
                                this.config.generate.copyTemplateConfig &&
                                extractConfigFiles(
                                    entry,
                                    targetAppDir,
                                    this.config.generate.copyTemplateConfig,
                                )
                            ) {
                                /// First Do Nothing )(
                                this.log.status(`file unpacked: ${entry.path}`)
                            } else {
                                const copyTemplates =
                                    typeof this.config.generate.copyTemplates === 'undefined'
                                        ? true
                                        : this.config.generate.copyTemplates
                                const copyPublic =
                                    typeof this.config.generate.copyPublic === 'undefined'
                                        ? true
                                        : this.config.generate.copyPublic

                                if (copyTemplates && outputPath.indexOf('templates/') === 0) {
                                    /// copy the templates files over to the /templates folder in the root applicaiton
                                    copyFileFromArchive(entry, targetAppDir, outputPath)

                                    this.log.status(`file unpacked: ${entry.path}`)
                                } else if (copyPublic && outputPath.indexOf('public/') === 0) {
                                    /// copy the public files over to the /public folder in the root applicaiton
                                    copyFileFromArchive(entry, targetAppDir, outputPath)

                                    this.log.status(`file unpacked: ${entry.path}`)
                                } else {
                                    entry.autodrain()
                                }
                            }
                        }

                        if (this.config.generate.copyTemplateConfig) {
                            generateClobfigJson(tempDir)
                        }
                    }

                    const privateConfigFile = join(targetAppDir, 'private.config.json')
                    if (this.config.generate.copyPrivateConfig && existsSync(privateConfigFile)) {
                        this.log.status(
                            `private configuration copied from application root into /config.`,
                        )
                        copyFileSync(
                            privateConfigFile,
                            join(targetAppDir, 'config', 'private.config.json'),
                        )
                    }

                    const restartMessage = 'configuration loaded, restart required'
                    this.log.status(restartMessage)
                    /// Restart/Reinitialize our app
                    return resolve(restartMessage)
                } catch (err) {
                    this.log.error(`Error while generating files for sync`, this.config.generate)
                    return resolve(err.message)
                }
            }

            return resolve()
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
