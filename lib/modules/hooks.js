/// Begin with the module name
const moduleName = 'hooks'

/// Name the module init method which is used in logging
function InitHooks(initial, hooksOpts = {}) {
    /// dependencies are scoped to the module itself
    const { existsSync } = require('fs')

    this.config.hooks = this.getCoreOpts(moduleName, hooksOpts, initial)

    /// TODO: Create the nonce strategy that validates against uuid hashes from the authentication module

    if (this.config.hooks.enabled) {
        const controllersFolder =
            this.config.hooks.controllersFolder || this.config.folders.controllersFolder

        if (existsSync(controllersFolder)) {
            this.log.info(`🔗 adding the hooks subdomain and controller`)
            this.config.subdomains['hooks'] = this.config.subdomains['hooks'] || {}
            this.config.subdomains['hooks'].controller = 'hooks'
            this.app.post(
                '/',
                this.requestHandler(
                    (req, res) => {
                        console.log('HOOKS REQUEST', { subdomain: res.locals.subdomain })
                    },
                    ['hooks'],
                ),
                this.isAuthenticatedHandler(),
            )

            const getHooksViewController = (view = 'index') => {
                return this.requestHandler(
                    (req, res) => {
                        if (view === 'profile' && !req.isAuthenticated()) return res.redirect('/')

                        const credentials = req.user
                        const loginData = {
                            credentials,
                            host: res.locals.host,
                            name: this.config.name,
                        }

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

module.exports = InitHooks
module.exports.module = 'hooks'
module.exports.description = `Sets up the application to run webhooks at hooks.[host]`
module.exports.defaults = false
module.exports.version = '0.0.1'
