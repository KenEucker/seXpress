/// Begin with the module name
const moduleName = 'config'

/// Name the module init method which is used in logging
function InitConfig(initial, infoOpts = {}) {
    this.config.ui = this.getCoreOpts('ui', infoOpts, initial)

    /// if login is enabled, set up it's routes
    if (this.config.ui.enabled) {
		const {join} = require('path')
		const {copyFileSync, existsSync, readFileSync, writeFileSync} = require('fs')
		const {getFromQueryOrPathOrBody} = require('../util')(this.config.appRoot)
		const self = this
		
		this.log.info(`📋 adding the config subdomain and controller`)
        this.config.subdomains[moduleName] = this.config.subdomains[moduleName] || {}
		this.config.subdomains[moduleName].controller = moduleName

		const removeSensitiveObjects = (config, disallowedKeys = []) => {
			const allowedObjectTypes = ['string', 'object', 'boolean']
			const out = {}
			const keys = Object.keys(config).sort((a,b) => a.localeCompare(b))

			keys.forEach((key) => {
				const keyType = typeof config[key]

				if (allowedObjectTypes.indexOf(keyType) !== -1 && disallowedKeys.indexOf(key) === -1) {
					out[key] = keyType === 'object' ? removeSensitiveObjects(config[key]) : config[key]
					// out[key] = keyType === 'string' ? out[key].replace(/\n/gi, '') : out[key]
				}
			})

			return out
		}
		
		const jsonEditorNodeModulesPath = join(
            process.cwd(),
            'node_modules',
            'jsoneditor',
			'dist',
		)
		const jsonEditorCssFileName = 'jsoneditor.min.css'
		const jsonEditorJsFileName = 'jsoneditor.min.js'

		/// copy the json editor dependency into the /public folder jsoneditor
		const jsonEditorCssFilePath = join(jsonEditorNodeModulesPath, jsonEditorCssFileName)
		const jsonEditorJsFilePath = join(jsonEditorNodeModulesPath, jsonEditorJsFileName)

		if (existsSync(jsonEditorJsFilePath) && existsSync(jsonEditorCssFilePath)) {
			const mkdirp = require('mkdirp')
			const publicCssDestinationPath = join(this.config.folders.publicFolder, 'css')
			const publicJsDestinationPath = join(this.config.folders.publicFolder, 'js')

			mkdirp.sync(publicCssDestinationPath)
			mkdirp.sync(publicJsDestinationPath)

			const jsonEditorCssFile = readFileSync(jsonEditorCssFilePath)
			const modifiedJsonEditorCssFile = jsonEditorCssFile.toString().replace(/img\/jsoneditor-icons.svg/g, '/public/img/jsoneditor-icons.svg')
			writeFileSync(join(publicCssDestinationPath, jsonEditorCssFileName), modifiedJsonEditorCssFile)
			// copyFileSync(jsonEditorCssFilePath, join(publicCssDestinationPath, jsonEditorCssFileName))
			copyFileSync(jsonEditorJsFilePath, join(publicJsDestinationPath, jsonEditorJsFileName))
		} else {

		}

        /// Intercept all head post requests on the config subdomain
        this.route(
            '/',
            (subdomain, req, res, host, next) => {
                return next()
            },
			['get', 'post', 'put', 'delete'][moduleName],
			true,
        )

        /// Pass whatever config is available along with the permissions to the config view
        this.route(
            '/:subdomain?',
            function configIndexHandler(subdomain, req, res, host, next) {
				subdomain = getFromQueryOrPathOrBody(req, 'subdomain', subdomain)

				const subdomainConfig = self.config.subdomains[subdomain]
				const configData = {
					subdomainConfig: removeSensitiveObjects(subdomainConfig),
					appConfig: removeSensitiveObjects(self.config, ['content']),
					authTokens: removeSensitiveObjects(self.authTokens),
				}
                return self.renderViewOrTemplate('config/index', { configData }, res)
			},
			'get',
            true,
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
