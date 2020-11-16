class ApiController {
    init(app) {
        this.app = app
    }

    /**
     * @swagger
     * /v1/wassup:
     *   post:
     *     produces:
     *       - application/json
     *     description: Can you dig?
     *     security:
     *       - basic: []
     *     responses:
     *       200:
     *         description: we can dig it
     */
    wassup(subdomain, req, res, host, next) {
        console.log('hHERHER')
        return res.send('Yo!')
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
     *         description: yo dawg
     *         schema:
     *           type: string
     *     description: Yo Yo
     *     responses:
     *       200:
     *         description: yo dawg, I heard you like text
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
        app.route('/v1/wassup', this.wassup, ['get', 'post'], true)
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
