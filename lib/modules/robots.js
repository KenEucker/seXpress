/// Begin with the module name
const moduleName = 'robots'

/// Name the module init method which is used in logging
function InitRobots(initial, robotsOpts = {}) {
    /// dependencies are scoped to the module itself
    const robots = require('express-robots-txt')

    this.config.robots = this.getCoreOpts(moduleName, robotsOpts, initial)

    this.app.use(robots(this.config.robots))

    this.log.debug(moduleName, `🤖 robots beware`, this.config.robots)
}

module.exports = InitRobots
module.exports.module = moduleName
module.exports.description = 'Manages requests coming from robots and sets the robots.txt file'
module.exports.defaults = [{ UserAgent: '*', Disallow: '/' }]
module.exports.version = '0.0.1'
