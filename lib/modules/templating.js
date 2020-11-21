const path = require('path')
const fs = require('fs')
const express = require('express')

const moduleName = 'templating'

module.exports = function (templatingOpts = {}) {
    this.config.templating = this.getCoreOpts(moduleName, templatingOpts, {
        indexControllerName: 'index',
        enabled:
            typeof this.config.templating === 'boolean'
                ? this.config.templating
                : !!this.config.templating,
        static: {
            index: false,
        },
    })
	// console.log({templating: this.config.templating})

    if (!!this.config.subdomains) {
        const self = this
        let indexHandler = function NONE() {}

        if (this.config.templating.headless) {
            indexHandler = function ERROR(subdomain, req, res, host, next) {
                const error = new Error('No head template')
                error.status = 404
                next(error)
            }
            this.log.info('🕶 	head requests will return 404')
        } else {
            indexHandler = function renderTemplate(subdomain, req, res, host, next) {
                const template = self.getTemplateNameFromSubdomain(subdomain)
                return self.templateHandler(template)(subdomain, req, res, host, next)
            }
            this.log.info('routing all basepath requests to configured templates', { indexHandler })
        }

        /// Final catchall for templated routes
        this.route('/', indexHandler)

        Object.keys(this.config.subdomains).forEach((subdomain) => {
            if (!!this.config.subdomains[subdomain]) {
                const subdomainTemplate = this.config.subdomains[subdomain].template

                if (!!subdomainTemplate) {
                    const subdomainTemplatePath = path.join(
                        this.config.folders.templatesFolder,
                        subdomainTemplate,
                    )

                    if (fs.existsSync(subdomainTemplatePath)) {
                        this.log.debug(`configuring static path for subdomain: ${subdomain}`, {
                            subdomainTemplate,
                            subdomainTemplatePath,
                        })
                        this.app.use(express.static(subdomainTemplatePath))
                        this.app.get(
                            subdomainTemplatePath,
                            this.requestHandler(
                                (sub, req, res, host, next) => {
                                    this.log.status(
                                        'forwarding subdomain template request to the correct template',
                                        subdomain,
                                    )
                                    next()
                                },
                                [subdomain],
                            ),
                        )
                    } else {
                        this.log.error('❗️	subdomain template not found', {
                            subdomain,
                            subdomainTemplatePath,
                        })
                    }
                } else {
                    this.log.error('❗️	subdomain template not set', {
                        subdomain,
                        subdomainTemplate,
                    })
                }
            } else {
                this.log.error('❗️	WARNING cannot configure subdomain', subdomain)
            }
        })
    }

    // All public content
    this.app.use('/public', express.static(this.config.folders.publicFolder))
    this.log.info('static route configured for public folder', this.config.folders.publicFolder)

    const baseOverride = path.join(this.config.folders.templatesFolder, 'base')
    this.log.debug(`configuring static path for the base override files`, baseOverride)
    this.app.use(express.static(baseOverride, this.config.templating.static))

    /// DEPRECATED this should have already been handled by the static path usage above, but wasn't previously
    // this.app.use("/public", (req, res) => {
    // 	this.log.debug("asset requested", req.url)
    // 	const file = (req.url =
    // 		req.url.indexOf("?") != -1 ?
    // 		req.url.substring(0, req.url.indexOf("?")) :
    // 		req.url)
    // 	return res.sendFile(
    // 		path.join(this.config.folders.publicFolder, req.url)
    // 	)
    // })

    this.log.debug(` supporting templating of views in the folder`, {
        folder: this.config.folders.templatesFolder,
        engine: this.app.get('view engine'),
    })
}

module.exports.module = 'templating'
module.exports.description = 'Adds templating to the app using [.liquid] by default'
