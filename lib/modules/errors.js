/// Begin with the module name
moduleName = 'errors'

/// Name the module init method which is used in logging
async function InitErrors(initial, errorsOpts = {}) {
    /// dependencies are scoped to the module itself
    const { express: httpErrorPages } = require('http-error-pages')
    const { join } = require('path')
    const { existsSync, readFileSync } = require('fs')

    this.config.errors = this.getCoreOpts(moduleName, errorsOpts, initial)

    /// Attaches an httpcode error handler template
    if (!this.config.debug) {
        let stylesheet, template
        const templatesErrorFolder = join(this.config.folders.templatesFolder, 'error')

        if (existsSync(templatesErrorFolder)) {
            const cssFilePath = join(templatesErrorFolder, 'error.css')
            /// TODO: change to .liquid
            const templateFilePath = join(templatesErrorFolder, 'error.ejs')

            if (existsSync(cssFilePath)) {
                stylesheet = readFileSync(cssFilePath)
                this.log.debug(moduleName, 'using custom css file for error pages', cssFilePath)
            }
            if (existsSync(templateFilePath)) {
                template = templateFilePath
                this.log.debug(
                    moduleName,
                    'using custom template file for error pages',
                    templateFilePath,
                )
            }
        }

        const filter = (data, req, res) => {
            // !this.config.templating.headless ?
            data.redirectTo = this.getHomeUrl(req)
            data.debug = data.error.message !== 'file not found' ? data.error.message : false
            data.nonce = res.locals.nonce

            return data
        }
        // : undefined
        this.log.debug(moduleName, `🚫 custom error pages will display to the end user`)

        /// Final route before sending http error page
        this.app.all('*', (req, res, next) => {
            this.log.status(`Error: path is not an accepted for host: ${req.hostname}${req.url}`)
            return next()
        })

        // use http error pages handler (final statement!)
        return httpErrorPages(this.app, {
            filter,
            template,
            stylesheet,
            // onError: (e) => {
            //     this.log.error(`Error page ${e.code} will be displayed: ${e.error.message}`)
            // },
            lang: this.config.lang || 'en_US',
            payload: {
                footer: `Care of <strong>${this.config.name}</strong>`,
            },
        })
    }
}

module.exports = InitErrors
module.exports.module = moduleName
module.exports.description = 'Attaches an httpcode error handler template'
module.exports.version = '0.0.1'
