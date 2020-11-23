const moduleName = 'roles'

module.exports = function InitRoles(initial, infoRoles = {}) {
    this.config.roles = this.getCoreOpts(moduleName, infoRoles, initial)

    if (this.config.roles.enabled) {
    }
}
module.exports.module = moduleName
module.exports.description = 'Manages the permissions of users and resources'
module.exports.defaults = false
