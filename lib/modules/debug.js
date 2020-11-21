const util = require('../util')()

const moduleName = 'debug'
// const htmlLog = require('console-log-html')

module.exports = function (debug = false) {
    /// This debug module should be the first thing loaded for sexpress, always.
    this._running = false

    // Never let debug mode run in production ?
    this.config.debug =
        typeof debug === 'undefined' || process.env.NODE_ENV === 'production' ? false : debug

    /// Set up the logger
    this.setLogger(util.log.setDebugging(this.config.debug))

    /// TODO: add console-log-html integration
    // htmlLog
}
module.exports.module = moduleName
module.exports.description = 'sets debugging information for the app when in debug mode'
