const routes = (app) => {
    app.routeSubdomainRequest('/:yo?', (subdomain, req, res, host) => {
        if (!subdomain) {
            const hostSubdomainEnd = host.indexOf('.') + 1
            const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

            console.log({
                subdomain,
                hostNotFound: host,
                redirectToHost,
            })

            return res.redirect(redirectToHost)
        }

		console.log({subdomain})
        const template = 'landing'
        const params = typeof req.params === 'object' ? req.params : {}
        const data = app.getPublicConfigurationValues(subdomain, host, params)

        return app.renderTemplate(template, data, res)
    })
}

module.exports = {
    engine: 'ejs',
    routes,
}
