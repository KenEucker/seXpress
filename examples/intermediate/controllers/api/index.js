const routes = (app) => {
    app.routeSubdomainRequest('/hello', (subdomain, req, res, host, next) => {
        const myError = new Error()
        myError.status = 403
        myError.message = 'AHDWAW'
        myError.title = 'IWUE'
        next(myError)
    })
}

module.exports = {
    engine: 'ejs',
    routes,
}
