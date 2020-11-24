/// Begin with the module name
const moduleName = 'routing'

/// Name the module init method which is used in logging
function InitRouting(initial, routingOpts = {}) {
    /// dependencies are scoped to the module itself
    const util = require('../util')(this.config.appRoot)
    const { existsSync } = require('fs')

    this.config.routing = this.getCoreOpts(
        moduleName,
        util.merge(routingOpts, {
            routesFolder: this.config.folders.controllersFolder,
        }),
        initial,
    )

    if (existsSync(this.config.routing.routesFolder)) {
        const controllers = util.getControllers(this.config, this.config.routing.routesFolder)

        controllers.forEach((file) => {
            const controller = require(file)
            const replaced = file.replace(`${this.config.routing.routesFolder}/index.js`, '')
            const isIndexController = !(replaced.length > 1)

            this.registerController(
                controller,
                isIndexController ? '' : util.getControllerNameFromFilePath(file),
            )
        })
    }
}

module.exports = InitRouting
module.exports.module = moduleName
module.exports.description = 'Adds dynamic routing functionality to the application'
module.exports.defaults = {
    indexControllerName: 'index',
}
module.exports.version = '0.0.1'
