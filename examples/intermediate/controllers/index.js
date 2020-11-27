const routes = (app) => {
    app.route('/:yo?', (subdomain, req, res, host) => {
        const template = app.getTemplateNameFromSubdomain(subdomain)
        const params = typeof req.params === 'object' ? req.params : {}
        const data = app.getPublicData(subdomain, host, params, res)

        return app.renderTemplate(template, data, res)
    })

    app.route('/yo/:yo?', function getYoYo(subdomain, req, res, host) {
        const params = typeof req.params === 'object' ? req.params : {}

        return res.render('yo', params)
    })
}

module.exports = {
    routes,
}
