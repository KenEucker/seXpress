const path = require('path')
const fs = require('fs')
const express = require('express')
const moduleName = 'templating'

module.exports = function InitTemplating(initial, templatingOpts = {}) {
	const util = require('../util')(this.config.appRoot)
	
	this.config.templating = this.getCoreOpts(moduleName, util.merge(templatingOpts, {
		enabled: typeof this.config.templating === 'boolean' ? this.config.templating : true,
    }), initial)

    if (!!this.config.subdomains && this.config.templating.enabled) {
        const self = this
        let indexHandler = function NONE() {}

        if (this.config.templating.headless) {
            indexHandler = function ERROR(subdomain, req, res, host, next) {
                const error = new Error('No head template')
                error.status = 404
                next(error)
            }
            this.log.info('🕶  head requests will return 404')
        } else {
            indexHandler = function renderTemplate(subdomain, req, res, host, next) {
                const template = self.getTemplateNameFromSubdomain(subdomain)
                return self.templateHandler(template)(subdomain, req, res, host, next)
            }
            this.log.info(
                `💫 routing all root requests to configured templates`,
                this.getSubdomainTemplateMaps(),
            )
        }

        /// Final catchall for templated routes
        this.route('/', indexHandler)

        Object.keys(this.config.subdomains).forEach((subdomain) => {
            if (!!this.config.subdomains[subdomain]) {
                const subdomainTemplate = this.config.subdomains[subdomain].template || subdomain

                if (!!subdomainTemplate) {
                    const subdomainTemplatePath = path.join(
                        this.config.folders.templatesFolder,
                        subdomainTemplate,
                    )

                    if (fs.existsSync(subdomainTemplatePath)) {
                        this.log.debug(`🚠 configuring static path for subdomain: ${subdomain}`, {
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

        this.log.debug(` supporting templating of views in the folder`, {
            folder: this.config.folders.templatesFolder,
            engine: this.app.get('view engine'),
        })
    }

    // All public content
    this.app.use('/public', express.static(this.config.folders.publicFolder))
    this.log.info(`🏔  static route configured for public folder`, this.config.folders.publicFolder)

    const baseOverride = path.join(this.config.folders.templatesFolder, 'base')
    this.log.debug(`🚠 configuring static path for the base override files`, baseOverride)
    this.app.use(express.static(baseOverride, this.config.templating.static))
}

module.exports.module = 'templating'
module.exports.description = 'Adds templating to the app using [.liquid] by default'
module.exports.defaults = {
	indexControllerName: 'index',
	static: {
		index: false,
	},
}
