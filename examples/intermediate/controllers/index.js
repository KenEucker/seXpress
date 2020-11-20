const routes = (app) => {
    app.route('/:yo?', (subdomain, req, res, host) => {
        const template = app.getTemplateNameFromSubdomain(subdomain)
        const params = typeof req.params === 'object' ? req.params : {}
        const data = app.getPublicConfig(subdomain, host, params)

		console.log({template, subdomain})
        return app.renderTemplate(template, data, res)
    })

    app.route('/yo/:yo?', function getYoYo(subdomain, req, res, host) {
        if (!subdomain) {
            const hostSubdomainEnd = host.indexOf('.') + 1
            const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

            app.log.error('Subdomain not set, redirecting to host', {
                subdomain,
                hostNotFound: host,
                redirectToHost,
            })

            return res.redirect(redirectToHost)
        }

        const params = typeof req.params === 'object' ? req.params : {}
        return res.render('yo', params)
    })
}

module.exports = {
    routes,
}
