/// Begin with the module name
const moduleName = 'info'

/// Name the module init method which is used in logging
function InitLogging(initial, loggingOpts = {}) {
    /// dependencies are scoped to the module itself
    const { logger } = this.middlewares.util

    this.config.logging = this.getCoreOpts(moduleName, loggingOpts, initial)

    if (this.config.logging.enabled) {
        if (this.config.logging.onlyLogErrors) {
            this.app.use(
                logger('combined', {
                    skip: function (req, res) {
                        if (
                            req.method.toLocaleLowerCase() === 'get' &&
                            new RegExp(this.config.logging.ignoreRoutes.join('|')).test(url)
                        ) {
                            return false
                        }

                        return res.statusCode < 400
                    },
                }),
            )
        } else {
            this.app.use(logger(this.config.debug ? 'dev' : 'tiny'))
        }

        this.log.debug(moduleName, `📝 console and local logging intialized`)
    }
}

module.exports = InitLogging
module.exports.module = moduleName
module.exports.description = 'Sets up internal and external logging'
module.exports.defaults = {
    ignoreRoutes: [
        '/public*',
        '/css*',
        '/js*',
        '/font*',
        '/webfont*',
        '/img*',
        '/media*',
        '/docs*',
        '/api/swagger.json',
    ],
}
module.exports.version = '0.0.1'
