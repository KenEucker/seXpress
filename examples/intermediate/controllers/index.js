const routes = (app) => {
    app.route('/:yo?', (req, res) => {
		const { host, subdomain } = res.locals
        const template = app.getTemplateNameFromSubdomain(subdomain)
        const params = typeof req.params === 'object' ? req.params : {}
        const data = app.getPublicData(subdomain, host, params, res)

        return app.renderTemplate(template, data, res)
    })

    app.route('/yo/:yo?', function getYoYo(req, res) {
        const params = typeof req.params === 'object' ? req.params : {}

        return res.render('yo', params)
    })
}

module.exports = {
    routes,
}
