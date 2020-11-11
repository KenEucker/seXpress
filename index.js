const Sexpress = require('./lib/sexpress')

const sexPressFactory = (opts = {}) => {
    const sexpress = new Sexpress(opts)

    return sexpress
}

module.exports = sexPressFactory
module.exports.Sexpress = Sexpress
