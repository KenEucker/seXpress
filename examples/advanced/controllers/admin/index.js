class AdminController {
    /**
     * @swagger
     * /get/:
     *   post:
     *     produces:
     *       - application/json
     *     parameters:
     *       - in: formData
     *         name: setting
     *         description: The setting
     *         schema:
     *           type: integer
     *     description: Retrieves the admin configuration setting
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

    /**
     * @swagger
     * /flush/:
     *   post:
     *     produces:
     *       - application/json
     *     parameters:
     *       - in: formData
     *         name: setting
     *         description: The setting
     *         schema:
     *           type: integer
     *     description: flushes the cache of the given setting or ALL
     *     responses:
     *       200:
     *         description: reddit post text
     */
    flushCache(subdomain, req, res, host, next) {
        return res.json({
            setting: req.params.setting,
            subdomain,
            host,
        })
    }

    getHooks() {
        return {
            '/flush/:setting?': this.flushCache,
        }
    }

    servePrivateDocumentation() {}

    routes(app) {
        app.route('/get/:setting', this.getSetting, ['get', 'post'], true)
    }
}

module.exports = new AdminController()
module.exports.hooks = module.exports.getHooks()
