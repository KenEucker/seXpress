const robots = require('express-robots-txt')

module.exports = function () {
    const robotsTxt = this.config.robots || [{ UserAgent: '*', Disallow: '/' }]
    this.app.use(robots(robotsTxt))
}
module.exports.module = 'robots'
module.exports.description = 'Manages requests coming from robots and sets the robots.txt file'
