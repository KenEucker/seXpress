const routes = (app) => {
    app.routeSubdomainRequest('/v3/:endpoint?', (subdomain, req, res, host, next) => {
        const myError = new Error()
        myError.status = 501
        myError.message = 'Version 3 not yet implemented'
        next(myError)
    })
}

module.exports = {
    engine: 'ejs',
    routes,
}
