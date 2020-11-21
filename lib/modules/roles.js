const moduleName = 'roles'

module.exports = function (infoOpts = {}) {
    this.config.roles = this.getCoreOpts(moduleName, infoOpts, false)

    if (this.config.roles.enabled) {
    }
}
module.exports.module = moduleName
module.exports.description = 'Manages the permissions of users and resources'
