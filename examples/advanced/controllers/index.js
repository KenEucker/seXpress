class SiteController {
    init(app) {
        this.app = app
        this.engine = 'ejs'
    }

    hello(subdomain, req, res, host) {
        if (!subdomain) {
            const hostSubdomainEnd = host.indexOf('.') + 1
            const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

            this.app.log.error({
                subdomain,
                hostNotFound: host,
                redirectToHost,
            })

            return res.redirect(redirectToHost)
        }

        const template = 'landing'
        const params = typeof req.params === 'object' ? req.params : {}
        const data = this.app.getPublicConfigurationValues(subdomain, host, params)

        return this.app.renderTemplate(template, data, res)
    }

    routes(app) {
        app.routeSubdomainRequest('/hello', this.hello)
    }
}

module.exports = new SiteController()
