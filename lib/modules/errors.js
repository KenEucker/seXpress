const httpErrorPages = require('http-error-pages')
const path = require('path')
const fs = require('fs')

moduleName = 'errors'

module.exports = async function InitErrors(initial, errorsOpts = {}) {
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
            return data
        }
        // : undefined
        this.log.debug(`🚫 custom error pages will display to the end user`)

        // use http error pages handler (final statement!)
        return httpErrorPages.express(this.app, {
            filter,
            onError: console.error,
            template,
            css,
            lang: this.config.lang || 'en_US',
            footer: `Care of <strong>${this.config.name}</strong>`,
        })
    }
}
module.exports.module = moduleName
module.exports.description = 'Attaches an httpcode error handler template'
