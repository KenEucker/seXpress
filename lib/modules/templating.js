const path = require('path')
const fs = require('fs')
const express = require('express')

module.exports = function () {
    if (!!this.config.subdomains) {
        let indexHandler = () => {}
        if (this.config.headless) {
            this.log.info('head requests will return 404')
            indexHandler = (subdomain, req, res, host, next) => {
                const error = new Error('No head template')
                error.status = 404
                next(error)
            }
        } else {
            this.log.info('routing all basepath requests to configued templates')
            indexHandler = (subdomain, req, res, host, next) => {
                const template = this.getTemplateNameFromSubdomain(subdomain)
                return this.templateHandler(template)(subdomain, req, res, host, next)
            }
        }

        /// Final catchall for templated routes
        this.route('/', indexHandler)

        Object.keys(this.config.subdomains).forEach((subdomain) => {
            if (!!this.config.subdomains[subdomain]) {
                const subdomainTemplate = this.config.subdomains[subdomain].template

                if (!!subdomainTemplate) {
                    const subdomainTemplatePath = path.join(
                        this.config.templatesFolder,
                        subdomainTemplate,
                    )

                    if (fs.existsSync(subdomainTemplatePath)) {
                        this.log.debug(
                            `configuring static path for subdomain: ${subdomain}`,
                            subdomainTemplatePath,
                        )
                        this.app.use(express.static(subdomainTemplatePath))
                    } else {
                        this.log.error('subdomain template not found', {
                            subdomain,
                            subdomainTemplatePath,
                        })
                    }
                } else {
                    this.log.error('subdomain template not set', {
                        subdomain,
                    })
                }
            } else {
                this.log.error('cannot configure subdomain', subdomain)
            }
        })
    }

    // All public content
    this.app.use('/public', express.static(this.config.publicFolder))
    this.log.info('static route configured for public folder', this.config.publicFolder)

    const baseOverride = path.join(this.config.templatesFolder, 'base')
    this.log.debug(`configuring static path for the base override files`, baseOverride)
    this.app.use(express.static(baseOverride))

    /// DEPRECATED this should have already been handled by the static path usage above, but wasn't previously
    // this.app.use("/public", (req, res) => {
    // 	this.log.debug("asset requested", req.url)
    // 	const file = (req.url =
    // 		req.url.indexOf("?") != -1 ?
    // 		req.url.substring(0, req.url.indexOf("?")) :
    // 		req.url)
    // 	return res.sendFile(
    // 		path.join(this.config.publicFolder, req.url)
    // 	)
    // })

    this.log.debug('finished templating set up for path', this.config.templatesFolder)
}
module.exports.module = 'templating'
module.exports.description = 'Adds templating to the app using [.liquid] by default'
