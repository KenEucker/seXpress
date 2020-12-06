class SiteController {
    hello(req, res) {
		const { host, subdomain } = res.locals
        const template = 'landing'
        const params = typeof req.params === 'object' ? req.params : {}
        const data = this.app.getPublicData(subdomain, host, params, res)

        return this.app.renderTemplate(template, data, res)
    }

    routes(app) {
        app.route('/hello', this.hello)
    }
}

module.exports = new SiteController()
