/// Begin with the module name
const moduleName = 'test'

/// Name the module init method which is used in logging
function InitTest(initial, testOpts = {}) {
    this.config.test = this.getCoreOpts(moduleName, testOpts, initial)

    /// The base testing method will send to the logger
    this.test = (q = 'undefined', s = (s) => s, m = '', v = '') =>
        this.log.debug(`${typeof q === 'object' ? q.name : q} ${m} ${v.toString()}`, { q, s, v, m })

    if (this.config.test.enabled) {
        /// this.test = mocha chai
    }
}

module.exports = InitTest
module.exports.module = moduleName
module.exports.description = 'Integration testing for sull suite application runtime testing'
module.exports.defaults = false
module.exports.version = '0.0.1'
