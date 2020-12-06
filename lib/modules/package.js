/// Begin with the module name
const moduleName = 'package'

/// Name the module init method which is used in logging
function InitPackage(initial, infoOpts = {}) {
    this.config.package = this.getCoreOpts(moduleName, infoOpts, initial)

    if (this.config.package.enabled) {
        /// remove all src files
        /// inject styles into all templates and views, then delete all style files
        /// Send the package to a release branch in github project linked in packagejson
        /// Save the release hash to the config.releases option
    }
}

module.exports = InitPackage
module.exports.module = moduleName
module.exports.description = 'Packages the sexpress application for concise deployment'
module.exports.defaults = false
module.exports.version = '0.0.1'
