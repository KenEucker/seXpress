/// Begin with the module name
const moduleName = 'database'

/// Name the module init method which is used in logging
function InitDatabase(initial, databaseOpts = {}) {
    this.config.database = this.getCoreOpts(moduleName, databaseOpts, initial)

    if (this.config.database.enabled) {
    }
}

module.exports = InitDatabase
module.exports.module = moduleName
module.exports.description = 'Manages the connection to databases used across the application'
module.exports.defaults = false
module.exports.version = '0.0.1'
