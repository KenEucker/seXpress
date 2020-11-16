module.exports = (only) => {
    const folder = __dirname
    const coreModules = {}
    const coreModuleFiles = require('fs')
        .readdirSync(folder)
        .filter((f) => only.indexOf(f.replace('.js', '')) !== -1)

    coreModuleFiles.map((filename) => {
        if (filename === 'index.js') return false

        coreModules[filename.replace('.js', '')] = require(`${folder}/${filename}`)
    })

    return coreModules
}
