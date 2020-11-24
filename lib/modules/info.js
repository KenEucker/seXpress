/// Begin with the module name
const moduleName = 'info'

/// Name the module init method which is used in logging
function InitInfo(initial, infoOpts = {}) {
    this.config.info = this.getCoreOpts(moduleName, infoOpts, initial)
}

module.exports = InitInfo
module.exports.module = moduleName
module.exports.description =
    'Add the info subdomain which provides json, yaml, rss, html, robots, and other feeds at info.hostname/:ext? json by default'
module.exports.defaults = false
module.exports.version = '0.0.1'
