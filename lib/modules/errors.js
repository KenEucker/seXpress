/// Begin with the module name
moduleName = 'errors'

/// Name the module init method which is used in logging
async function InitErrors(initial, errorsOpts = {}) {
    /// dependencies are scoped to the module itself
    const httpErrorPages = require('http-error-pages')
    const { join } = require('path')
    const { existsSync } = require('fs')

    this.config.errors = this.getCoreOpts(moduleName, errorsOpts, initial)

    /// Attaches an httpcode error handler template
    if (!this.config.debug) {
        let css, template
        const templatesErrorFolder = join(this.config.folders.templatesFolder, 'error')

        if (existsSync(templatesErrorFolder)) {
            const cssFilePath = join(templatesErrorFolder, 'error.css')
            /// TODO: change to .liquid
            const templateFilePath = join(templatesErrorFolder, 'template.ejs')

            if (existsSync(cssFilePath)) {
                css = cssFilePath
                this.log.debug('using custom css file for error pages', cssFilePath)
            }
            if (existsSync(templateFilePath)) {
                template = templateFilePath
                this.log.debug('using custom css file for error pages', templateFilePath)
            }
        }

        const filter = (data, req) => {
            // !this.config.templating.headless ?
            data.redirectTo = this.getHomeUrl(req)
            data.debug = data.error.message !== 'file not found' ? data.error.message : false

            return data
        }
        // : undefined
        this.log.debug(`🚫 custom error pages will display to the end user`)

        /// Final route before sending http error page
        this.app.all('*', (req, res, next) => {
            this.log.status(`Error: path is not an accepted for host: ${req.hostname}${req.url}`)
            return next()
        })

        // use http error pages handler (final statement!)
        return httpErrorPages.express(this.app, {
            filter,
            template,
            css,
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
