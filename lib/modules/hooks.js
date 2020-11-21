const fs = require('fs')

const moduleName = 'hooks'

module.exports = function (hooksOpts = {}) {
    this.config.hooks = this.getCoreOpts(moduleName, hooksOpts, false)

    /// TODO: Create the nonce strategy that validates against uuid hashes from the authentication module

    if (this.config.hooks.enabled) {
        const controllersFolder =
            this.config.hooks.controllersFolder || this.config.folders.controllersFolder

        if (fs.existsSync(controllersFolder)) {
            this.log.info(`🔗 adding the hooks subdomain and controller`)
            this.config.subdomains['hooks'] = this.config.subdomains['hooks'] || {}
            this.config.subdomains['hooks'].controller = 'hooks'
            this.app.post(
                '/',
                this.requestHandler(
                    (subdomain, req, res, host, next) => {
                        console.log('HOOKS REQUEST', { subdomain })
                    },
                    ['hooks'],
                ),
                this.isAuthenticatedHandler(),
            )

            const getHooksViewController = (view = 'index') => {
                return this.requestHandler(
                    (subdomain, req, res, host, next) => {
                        if (view === 'profile' && !req.isAuthenticated()) return res.redirect('/')

                        const credentials = req.user
                        const loginData = { credentials, host, appName: this.config.appName }

                        const hookData = this.hooks.map((hook) => {
                            console.log({ hook })
                        })

                        return this.renderViewOrTemplate(`hooks/${view}`, hookData, res)
                    },
                    ['hooks'],
                )
            }
            this.app.get('/', getHooksViewController())
        }
    }
}
module.exports.module = 'hooks'
module.exports.description = `Sets up the application to run webhooks at hooks.[host]`
