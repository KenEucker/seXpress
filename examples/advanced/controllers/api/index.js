class ApiController {
    init(app) {
        this.app = app
        this.engine = 'ejs'
    }

    routes(app) {
        app.routeSubdomainRequest('/v3/:endpoint?', function NotImplemented(
            subdomain,
            req,
            res,
            host,
            next,
        ) {
            const myError = new Error()
            myError.status = 501
            myError.message = 'Version 3 not yet implemented'

            next(myError)
        })
    }
}

module.exports = new ApiController()
