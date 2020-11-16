const { logger } = require('../util')()

module.exports = function () {
    if (this.config.onlyLogErrors) {
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
}
module.exports.module = 'logging'
module.exports.description = 'Sets up internal and external logging'
