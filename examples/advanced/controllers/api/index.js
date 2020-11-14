class ApiController {
    init(app) {
        this.app = app
        this.engine = 'ejs'
    }

    /**
     * @swagger
     * /v1/yo/{yo}:
     *   post:
     *     produces:
     *       - application/json
     *     parameters:
     *       - in: path
     *         name: yo
     *         description: the tag nunber to retrieve
     *         schema:
     *           type: integer
     *     description: Retrieves the reddit post template for the given tag number, or latest
     *     responses:
     *       200:
     *         description: reddit post text
     */
    yo(subdomain, req, res, host, next) {
        return res.json({
            yo: req.params.yo,
            subdomain,
            host,
        })
    }

    routes(app) {
        app.route('/v1/yo/:yo?', this.yo, 'post')
        app.route(
            '/v3/:endpoint?',
            function NotImplemented(subdomain, req, res, host, next) {
                const myError = new Error()
                myError.status = 501
                myError.message = 'Version 3 not yet implemented'

                next(myError)
            },
            'post',
        )
    }
}

module.exports = new ApiController()
