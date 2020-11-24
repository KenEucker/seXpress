const httpErrorPages = require('http-error-pages')
const path = require('path')
const fs = require('fs')

moduleName = 'errors'

async function InitErrors(initial, errorsOpts = {}) {
    this.config.errors = this.getCoreOpts(moduleName, errorsOpts, initial)

    /// Attaches an httpcode error handler template
    if (!this.config.debug) {
        let css, template
        const templatesErrorFolder = path.join(this.config.folders.templatesFolder, 'error')

        if (fs.existsSync(templatesErrorFolder)) {
            const cssFilePath = path.join(templatesErrorFolder, 'error.css')
            /// TODO: change to .liquid
            const templateFilePath = path.join(templatesErrorFolder, 'template.ejs')

            if (fs.existsSync(cssFilePath)) {
                css = cssFilePath
                this.log.debug('using custom css file for error pages', cssFilePath)
            }
            if (fs.existsSync(templateFilePath)) {
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
            onError: (e) => {
                this.log.error(`Error page ${e.code} will be displayed: ${e.error.message}`)
            },
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
module.exports.version = "0.0.1"
