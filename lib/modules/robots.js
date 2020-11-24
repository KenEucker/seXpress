const robots = require('express-robots-txt')

const moduleName = 'robots'

function InitRobots(initial, robotsOpts = {}) {
    this.config.robots = this.getCoreOpts(moduleName, robotsOpts, initial)

    this.app.use(robots(this.config.robots))

    this.log.debug(`🤖 robots beware`, this.config.robots)
}

module.exports = InitRobots
module.exports.module = moduleName
module.exports.description = 'Manages requests coming from robots and sets the robots.txt file'
module.exports.defaults = [{ UserAgent: '*', Disallow: '/' }]
module.exports.version = '0.0.1'
