const fs = require('fs')
const { getControllers, getControllerNameFromFilePath } = require('../util')()

module.exports = function (controllersFolder) {
    controllersFolder = controllersFolder || this.config.controllersFolder

    if (fs.existsSync(controllersFolder)) {
        const controllers = getControllers(this.config, controllersFolder)

        controllers.forEach((file) => {
            const controller = require(file)
            const replaced = file.replace(`${this.config.controllersFolder}/index.js`, '')
            const isIndexController = !(replaced.length > 1)

            this.registerController(
                controller,
                isIndexController ? '' : getControllerNameFromFilePath(file),
            )
        })
    }
}
module.exports.module = 'routing'
module.exports.description = 'Adds dynamic routing functionality to the application'
