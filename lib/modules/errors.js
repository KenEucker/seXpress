const httpErrorPages = require('http-error-pages')
const path = require('path')
const fs = require('fs')

module.exports = async function () {
    /// Attaches an httpcode error handler template
    if (!this.config.debug) {
        let css, template
        const templatesErrorFolder = path.join(this.config.templatesFolder, 'error')

        if (fs.existsSync(templatesErrorFolder)) {
			const cssFilePath = path.join(templatesErrorFolder, 'error.css')
			/// TODO: change to .liquid
            const templateFilePath = path.join(templatesErrorFolder, 'template.ejs')

            // if (fs.existsSync(cssFilePath)) {
            // 	css = cssFilePath
            // 	this.log.info('using custom css file for error pages', cssFilePath)
            // }
            if (fs.existsSync(templateFilePath)) {
                template = templateFilePath
                this.log.info('using custom css file for error pages', templateFilePath)
            }
        }

        const filter = (data, req) => {
            // !this.config.headless ?
            data.redirectTo = `${req.protocol}://${req.get('host')}`
            return data
        }
        // : undefined

        // use http error pages handler (final statement!)
        await httpErrorPages.express(this.app, {
            filter,
            onError: console.error,
            template,
            css,
            lang: this.config.lang || 'en_US',
            footer: `Care of <strong>${this.config.appName}</strong>`,
        })
    }
}
module.exports.module = 'errors'
module.exports.description = 'Attaches an httpcode error handler template'
