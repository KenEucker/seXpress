class SiteController {
    hello(subdomain, req, res, host) {
        if (!subdomain) {
            const hostSubdomainEnd = host.indexOf('.') + 1
            const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

            this.app.log.error('Subdomain not set, redirecting to host', {
                subdomain,
                hostNotFound: host,
                redirectToHost,
            })

            return res.redirect(redirectToHost)
        }

        const template = 'landing'
        const params = typeof req.params === 'object' ? req.params : {}
        const data = this.app.getPublicConfig(subdomain, host, params)

        return this.app.renderTemplate(template, data, res)
    }

    routes(app) {
        app.route('/hello', this.hello)
    }
}

module.exports = new SiteController()
