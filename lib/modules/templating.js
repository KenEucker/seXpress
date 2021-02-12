/// Begin with the module name
const moduleName = 'templating'

/// Name the module init method which is used in logging
function InitTemplating(initial, templatingOpts = {}) {
    /// dependencies are scoped to the module itself
    const express = require('express')
    const { join } = require('path')
    const { existsSync } = require('fs')
    const { merge } = this.middlewares.util

    this.config.templating = this.getCoreOpts(
        moduleName,
        merge(templatingOpts, {
            enabled: typeof this.config.templating === 'boolean' ? this.config.templating : true,
        }),
        initial,
    )

    if (!!this.config.subdomains && this.config.templating.enabled) {
        const self = this
        let indexHandler = function NONE() {}

        if (this.config.templating.headless) {
            indexHandler = function ERROR(req, res, next) {
                const error = new Error('No head template')
                error.status = 404
                error.stack = error.stack.replace(/.*node_modules.*\n/g, '')
                next(error)
            }
            this.log.info('🕶  head requests will return 404')
        } else {
            indexHandler = function renderTemplate(req, res, next) {
                const template = self.getTemplateNameFromSubdomain(res.locals.subdomain)
                // this.log.debug('indexHandler', { template })

                return self.templateHandler(template)(req, res, next)
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
                    const subdomainTemplatePath = join(
                        this.config.folders.templatesFolder,
                        subdomainTemplate,
                    )

                    if (existsSync(subdomainTemplatePath)) {
                        this.app.get(
                            subdomainTemplatePath,
                            this.requestHandler(
                                (req, res, next) => {
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
                this.log.error('❗️	WARNING cannot configure subdomain for templating', subdomain)
            }
        })

        this.log.debug(moduleName, ` supporting templating of views in the folder`, {
            folder: this.config.folders.templatesFolder,
            engine: this.app.get('view engine'),
        })
    }

    // All public content
    this.app.use('/public', express.static(this.config.folders.publicFolder))
    this.log.info(`🏔  static route configured for public folder`, this.config.folders.publicFolder)

    const baseOverride = join(this.config.folders.templatesFolder, 'base')
    this.log.debug(
        moduleName,
        `🚠 configuring static path for the base override files`,
        baseOverride,
    )
    this.app.use(express.static(baseOverride, this.config.templating.static))
}

module.exports = InitTemplating
module.exports.module = moduleName
module.exports.description = 'Adds templating to the app using [.liquid] by default'
module.exports.defaults = {
    static: {
        index: false,
    },
}
module.exports.version = '0.0.1'
