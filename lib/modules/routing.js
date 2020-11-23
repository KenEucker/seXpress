const fs = require('fs')

const moduleName = 'routing'
module.exports = function InitRouting(initial, routingOpts = {}) {
    const util = require('../util')(this.config.appRoot)
    this.config.routing = this.getCoreOpts(
        moduleName,
        util.merge(routingOpts, {
            routesFolder: this.config.folders.controllersFolder,
        }),
        initial,
    )

    if (fs.existsSync(this.config.routing.routesFolder)) {
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
module.exports.module = moduleName
module.exports.description = 'Adds dynamic routing functionality to the application'
