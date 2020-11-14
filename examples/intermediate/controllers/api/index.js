const routes = (app) => {
    app.route('/yo/:yo?', (subdomain, req, res, host, next) => {
        res.json({
            params: req.params,
            subdomain,
            host,
        })
    })
}

module.exports = {
    routes,
}
