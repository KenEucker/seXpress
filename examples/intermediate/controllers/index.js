const routes = (app) => {
    app.route('/:yo?', (subdomain, req, res, host) => {
        if (!subdomain) {
            const hostSubdomainEnd = host.indexOf('.') + 1
            const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

            app.log.error({
                subdomain,
                hostNotFound: host,
                redirectToHost,
            })

            return res.redirect(redirectToHost)
        }

        const template = app.getTemplateNameFromSubdomain(subdomain)
        const params = typeof req.params === 'object' ? req.params : {}
        const data = app.getPublicConfig(subdomain, host, params)

        return app.renderTemplate(template, data, res)
    })

    app.route('/yo/:yo?', function getYoYo(subdomain, req, res, host) {
        if (!subdomain) {
            const hostSubdomainEnd = host.indexOf('.') + 1
            const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

            app.log.error({
                subdomain,
                hostNotFound: host,
                redirectToHost,
            })

            return res.redirect(redirectToHost)
        }

        const params = typeof req.params === 'object' ? req.params : {}
        return res.render('yo.ejs', params)
    })
}

module.exports = {
    routes,
}
