const moduleName = 'debug'
// const htmlLog = require('console-log-html')

/// The debug module accepts a single flag only, no opts
/// We don't name this one because debug should stand out
module.exports = function (debug = false) {
    const { log } = this.middlewares.util

    /// This debug module should be the first thing loaded for sexpress, always.
    this._running = false

    // Never let debug mode run in production ?
    this.config.debug =
        typeof debug === 'undefined' || process.env.NODE_ENV === 'production' ? false : debug

    /// Set up the logger
    this.setLogger(log.setDebugging(this.config.debug))

    /// TODO: add console-log-html integration, only authenticated admins can see this
    // htmlLog
}

module.exports.module = moduleName
module.exports.description = 'sets debugging information for the app when in debug mode'
module.exports.defaults = false
module.exports.version = '0.0.1'
