const passport = require('passport')

module.exports = function () {
    passport.serializeUser((user, done) => {
        done(null, user)
    })

    passport.deserializeUser((obj, done) => {
        done(null, obj)
    })

    if (this.config.security.enabled) {
        this.log.info('adding the login subdomain and controller')
        this.config.subdomains['login'] = this.config.subdomains['login'] || {}
        this.config.subdomains['login'].controller = 'login'
        this.app.post(
            '/',
            this.requestHandler((subdomain, req, res, host, next) => {
                if (subdomain === 'login') return next()
            }),
            passport.authenticate('local', {
                failureRedirect: '/?error=true',
                successRedirect: '/profile?success=true',
                failureFlash: true,
            }),
        )

        const getLoginViewController = (view = 'index') => {
            return this.requestHandler((subdomain, req, res, host, next) => {
                if (subdomain !== 'login') return next()

                const credentials = req.user
                const loginData = { credentials, host, appName: this.config.appName }

                return this.renderViewOrTemplate(`login/${view}`, loginData, res)
            })
        }
        this.app.get('/', getLoginViewController())
        this.app.get('/profile', getLoginViewController('profile'))
    }
}
module.exports.module = 'login'
module.exports.description = 'Add the login subdomain controller and user validation methods'
