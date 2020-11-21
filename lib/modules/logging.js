const { logger } = require('../util')()
const moduleName = 'info'

module.exports = function (loggingOpts = {}) {
    this.config.logging = this.getCoreOpts(moduleName, loggingOpts, {})

    if (this.config.logging.onlyLogErrors) {
        this.app.use(
            logger('combined', {
                skip: function (req, res) {
                    return res.statusCode < 400
                },
            }),
        )
    } else {
        this.app.use(logger(this.config.debug ? 'dev' : 'tiny'))
    }

    this.log.debug(`📝 console and local logging intialized`)
}
module.exports.module = moduleName
module.exports.description = 'Sets up internal and external logging'
