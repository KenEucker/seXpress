const nodeCache = require('node-cache')

module.exports = function () {
    this.cache = new nodeCache({
        stdTTL: this.config.cacheTTL ? this.config.cacheTTL : 60000,
    })
}
module.exports.module = 'cache'
module.exports.description = `Initializes the app's cache`
