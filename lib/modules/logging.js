const moduleName = 'info'

module.exports = function InitLogging(initial, loggingOpts = {}) {
    this.config.logging = this.getCoreOpts(moduleName, loggingOpts, initial)
	const util = require('../util')(this.config.appRoot)

    if (this.config.logging.enabled) {
        if (this.config.logging.onlyLogErrors) {
            this.app.use(
                logger('combined', {
                    skip: function (req, res) {
                        return res.statusCode < 400
                    },
                }),
            )
        } else {
            this.app.use(util.logger(this.config.debug ? 'dev' : 'tiny'))
        }

        this.log.debug(`📝 console and local logging intialized`)
    }
}
module.exports.module = moduleName
module.exports.description = 'Sets up internal and external logging'
