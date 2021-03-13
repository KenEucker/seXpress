/// Begin with the module name
const moduleName = 'config'

/// Name the module init method which is used in logging
function InitConfig(initial, infoOpts = {}) {
    this.config.ui = this.getCoreOpts('ui', infoOpts, initial)

    /// if login is enabled, set up it's routes
    if (this.config.ui.enabled) {
        const { join } = require('path')
        const { copyFileSync, existsSync, readFileSync, writeFileSync } = require('fs')
        const { getFromQueryOrPathOrBody, getSubdomainPrefix } = this.middlewares.util
        const self = this

        this.log.info(`📋 adding the config subdomain and controller`)
        this.registerCoreSubdomain(moduleName)
        this.config.subdomains[moduleName] = this.config.subdomains[moduleName] || {}
        this.config.subdomains[moduleName].controller = moduleName

        const removeSensitiveObjects = (config = {}, disallowedKeys = []) => {
            const allowedObjectTypes = ['string', 'object', 'boolean']
            const out = {}
            const keys = Object.keys(config).sort((a, b) => a.localeCompare(b))

            keys.forEach((key) => {
                const keyType = typeof config[key]

                if (
                    allowedObjectTypes.indexOf(keyType) !== -1 &&
                    disallowedKeys.indexOf(key) === -1
                ) {
                    out[key] =
                        config[key] !== null && keyType === 'object'
                            ? removeSensitiveObjects(config[key])
                            : config[key]
                    // out[key] = keyType === 'string' ? out[key].replace(/\n/gi, '') : out[key]
                }
            })

            return out
        }

        const jsonEditorNodeModulesPath = join(process.cwd(), 'node_modules', 'jsoneditor', 'dist')
        const jsonEditorCssFileName = 'jsoneditor.min.css'
        const jsonEditorJsFileName = 'jsoneditor.min.js'
        const jsonEditorSvgFileName = 'jsoneditor-icons.svg'

        /// copy the json editor dependency into the /public folder jsoneditor
        const jsonEditorCssFilePath = join(jsonEditorNodeModulesPath, jsonEditorCssFileName)
        const jsonEditorJsFilePath = join(jsonEditorNodeModulesPath, jsonEditorJsFileName)
        const jsonEditorSvgFileNamePath = join(
            jsonEditorNodeModulesPath,
            'img',
            jsonEditorSvgFileName,
        )

        if (existsSync(jsonEditorJsFilePath) && existsSync(jsonEditorCssFilePath)) {
            const mkdirp = require('mkdirp')
            const publicCssDestinationPath = join(this.config.folders.publicFolder, 'css')
            const publicJsDestinationPath = join(this.config.folders.publicFolder, 'js')
            const publicImgDestinationPath = join(this.config.folders.publicFolder, 'img')

            mkdirp.sync(publicCssDestinationPath)
            mkdirp.sync(publicJsDestinationPath)
            mkdirp.sync(publicImgDestinationPath)

            const jsonEditorCssFile = readFileSync(jsonEditorCssFilePath)
            const svgFileRegex = new RegExp(`img/${jsonEditorSvgFileName}`, 'g')
            const modifiedJsonEditorCssFile = jsonEditorCssFile
                .toString()
                .replace(svgFileRegex, `/public/img/${jsonEditorSvgFileName}`)
            writeFileSync(
                join(publicCssDestinationPath, jsonEditorCssFileName),
                modifiedJsonEditorCssFile,
            )
            copyFileSync(jsonEditorJsFilePath, join(publicJsDestinationPath, jsonEditorJsFileName))

            if (existsSync(jsonEditorSvgFileNamePath)) {
                copyFileSync(
                    jsonEditorSvgFileNamePath,
                    join(publicImgDestinationPath, jsonEditorSvgFileName),
                )
            }
        }

        /// Pass whatever config is available along with the permissions to the config view
        this.route(
            '/:subdomain?',
            async function configIndexHandler(req, res, next) {
                const subdomain = res.locals.subdomain

                if (subdomain === 'config' && self.isAuthenticated(req)) {
                    const configSubdomain = getFromQueryOrPathOrBody(req, 'subdomain', subdomain)

                    await self.setRedisValue('test', 'testValue')

                    const configDataPage = {
                        origin: self.getBaseUrl(true),
                        configData: {
                            appConfig: removeSensitiveObjects(self.config, ['content']),
                            authTokens: removeSensitiveObjects(self.authTokens),
                            redis: await self.getRedisKeys(),
                            redis2: await self.getRedisValues('test'),
                        },
                    }

                    if (configSubdomain !== 'config') {
                        const subdomainConfig = self.config.subdomains[configSubdomain]

                        configDataPage.configData.subdomainConfig = removeSensitiveObjects(
                            subdomainConfig,
                        )
                        configDataPage.configData.host = subdomainConfig.host
                    }

                    return self.renderTemplateOrView('config/index', configDataPage, res)
                } else if (subdomain === 'config') {
                    res.redirect('/login')
                }

                next()
            },
            'get',
            undefined,
            [moduleName],
        )
    }
}

module.exports = InitConfig
module.exports.module = moduleName
module.exports.description =
    'Add the config subdomain which provides a json editor and public view of the public data for the site and given subdomain'
module.exports.defaults = false
module.exports.version = '0.0.1'
