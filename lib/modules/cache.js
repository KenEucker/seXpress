const nodeCache = require('node-cache')

const moduleName = 'cache'

module.exports = function (cacheOpts = {}) {
    this.config.cache = this.getCoreOpts(moduleName, cacheOpts, {
        stdTTL: this.config.cacheTTL ? this.config.cacheTTL : 60000,
    })

    this.cache = new nodeCache(this.config.cache)

    this.log.debug(`🗄 internal cache initialized`, this.config.cache)
}
module.exports.module = moduleName
module.exports.description = `Initializes the app's cache`
