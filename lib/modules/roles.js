/// Begin with the module name
const moduleName = 'roles'

/// Name the module init method which is used in logging
function InitRoles(initial, rolesOpts = {}) {
    this.config.roles = this.getCoreOpts(moduleName, rolesOpts, initial)

    if (this.config.roles.enabled) {
    }
}

module.exports = InitRoles
module.exports.module = moduleName
module.exports.description = 'Manages the permissions of users and resources'
module.exports.defaults = false
module.exports.version = '0.0.1'
