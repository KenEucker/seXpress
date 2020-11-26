module.exports = (only) => {
    const folder = __dirname
    const middlewares = {}
    const middlewaresFiles = require('fs')
        .readdirSync(folder)
        .filter((f) => only.indexOf(f.replace('.js', '')) !== -1)

    middlewaresFiles.map((filename) => {
        if (filename === 'index.js') return false

        middlewares[filename.replace('.js', '')] = require(`${folder}/${filename}`)
    })

    return middlewares
}
