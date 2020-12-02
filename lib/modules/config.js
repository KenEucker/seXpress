/// Begin with the module name
const moduleName = 'config'

/// Name the module init method which is used in logging
function InitConfig(initial, infoOpts = {}) {
    this.config.ui = this.getCoreOpts('ui', infoOpts, initial)

    /// if login is enabled, set up it's routes
    if (this.config.ui.enabled) {
        const self = this
        this.log.info(`📋 adding the config subdomain and controller`)
        this.config.subdomains[moduleName] = this.config.subdomains[moduleName] || {}
        this.config.subdomains[moduleName].controller = moduleName

        /// copy the json editor dependency into the /public folder jsoneditor

        /// Intercept all head post requests on the login subdomain
        this.route(
            '/',
            (subdomain, req, res, host, next) => {
                return next()
            },
            ['get', 'post', 'put', 'delete'][moduleName],
        )

        /// Pass whatever config is available along with the permissions to the config view
        this.route(
            '/',
            function configIndexHandler(subdomain, req, res, host, next) {
                const subdomainConfig = self.config.subdomains[subdomain]
                let configData = {}
                if (req.isAuthenticated()) {
                }

                return res.render('config', configData)
            },
            true,
            [moduleName],
        )
    }
}

module.exports = InitConfig
module.exports.module = moduleName
module.exports.description =
    'Add the config subdomain which provides a json editor and public view of the public data for the site and given subdomain'
module.exports.defaults = false
module.exports.version = '0.0.1'
