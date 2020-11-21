const moduleName = 'info'

module.exports = function (infoOpts = {}) {
    this.config.info = this.getCoreOpts(moduleName, infoOpts, false)
}
module.exports.module = moduleName
module.exports.description =
    'Add the info subdomain which provides json, yaml, rss, html, robots, and other feeds at info.hostname/:ext? json by default'
