const routes = (app) => {
    app.route('/yo/:yo?', (req, res) => {
        res.json({
            params: req.params,
            subdomain: res.locals.subdomain,
            host: res.locals.host,
        })
    })

    /**
     * @swagger
     * /yo:
     *   post:
     *     produces:
     *       - application/json
     *     parameters:
     *       - in: formData
     *         name: yo
     *         description: yo dawg
     *         schema:
     *           type: string
     *     description: Yo Yo
     *     responses:
     *       200:
     *         description: yo dawg, I heard you like text
     *       401:
     *         $ref: '#/components/responses/UnauthorizedError'
     */
    app.apiRoute(
        '/yo',
        (req, res) => {
            res.json({
                params: req.params,
                subdomain: res.locals.subdomain,
                host: res.locals.host,
            })
        },
        'post',
    )
}

module.exports = {
    routes,
}
