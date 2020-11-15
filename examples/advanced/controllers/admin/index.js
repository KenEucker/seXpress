class AdminController {
    init(app) {
        this.app = app
    }

    /**
     * @swagger
     * /get/{setting}:
     *   post:
     *     produces:
     *       - application/json
     *     parameters:
     *       - in: path
     *         name: setting
     *         description: The setting
     *         schema:
     *           type: integer
     *     description: Retrieves the reddit post template for the given tag number, or latest
     *     responses:
     *       200:
     *         description: reddit post text
     */
    getSetting(subdomain, req, res, host, next) {
        return res.json({
            setting: req.params.setting,
            subdomain,
            host,
        })
    }

    servePrivateDocumentation() {}

    routes(app) {
        app.route('/get/:setting', this.getSetting, ['get', 'post'], true)
    }
}

module.exports = new AdminController()
