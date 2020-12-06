/// Begin with the module name
const moduleName = 'cache'

/// Name the module init method which is used in logging
function InitCache(initial, cacheOpts = {}) {
    this.config.cache = this.getCoreOpts(moduleName, cacheOpts, initial)

    /// dependencies are scoped to the module itself
    const nodeCache = require('node-cache')

    /// TODO: add the nonce expiry method and initialise with the options:
    /// 5 hours before tip*, and then 5 minutes after *tip or after 5 @taps
    /// tip: a notification from the hook module that the hook has completed processing the request
    /// tap: a checking of the nonce URL returned from a hook request
    /// nonce URL: uniquely generated hash from the uuid hash of the requested user (or current datetime) used for special handshake

    this.cache = new nodeCache(this.config.cache)

    this.log.debug(moduleName, `🗄  internal cache initialized`, this.config.cache)
}

module.exports = InitCache
module.exports.module = moduleName
module.exports.description = `Initializes the app's cache`
module.exports.defaults = {
    stdTTL: 60000,
}
module.exports.version = '0.0.1'
