/// Begin with the module name
const moduleName = 'static'

/// Name the module init method which is used in logging
function InitStatic(initial, staticOpts = {}) {
    this.config.static = this.getCoreOpts(moduleName, staticOpts, initial)

    if (this.config.static.enabled) {
        const { existsSync } = require('fs')
        const { join } = require('path')
        const { static } = require('express')

        Object.keys(this.config.subdomains).forEach((subdomain) => {
            if (!!this.config.subdomains[subdomain]) {
                const subdomainTemplate = this.config.subdomains[subdomain].template || subdomain

                if (!!subdomainTemplate) {
                    const subdomainTemplatePath = join(
                        this.config.folders.templatesFolder,
                        subdomainTemplate,
                    )

                    if (existsSync(subdomainTemplatePath)) {
                        this.log.debug(
                            moduleName,
                            `🚠 configuring static path for subdomain: ${subdomain}`,
                            {
                                subdomainTemplate,
                                subdomainTemplatePath,
                            },
                        )
                        this.app.use(static(subdomainTemplatePath))
                    }
                }
            }
        })
    }
}

module.exports = InitStatic
module.exports.module = moduleName
module.exports.description =
    'Add the info subdomain which provides json, yaml, rss, html, robots, and other feeds at info.hostname/:ext? json by default'
module.exports.defaults = true
module.exports.version = '0.0.1'
