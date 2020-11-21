const nodeCache = require('node-cache')

const moduleName = 'cache'

module.exports = function (cacheOpts = {}) {
    this.config.cache = this.getCoreOpts(moduleName, cacheOpts, {
        stdTTL: this.config.cacheTTL ? this.config.cacheTTL : 60000,
    })

    /// TODO: add the nonce expiry method and initialise with the options:
    /// 5 hours before tip*, and then 5 minutes after *tip or after 5 @taps
    /// tip: a notification from the hook module that the hook has completed processing the request
    /// tap: a checking of the nonce URL returned from a hook request
    /// nonce URL: uniquely generated hash from the uuid hash of the requested user (or current datetime) used for special handshake

    this.cache = new nodeCache(this.config.cache)

    this.log.debug(`🗄  internal cache initialized`, this.config.cache)
}
module.exports.module = moduleName
module.exports.description = `Initializes the app's cache`
