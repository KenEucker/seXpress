const passport = require('passport')

module.exports = function () {
    passport.serializeUser((user, done) => {
        /// TODO: set approrpiate domains for user role
        // console.log({serializeUser: user})
        done(null, user)
    })

    passport.deserializeUser((obj, done) => {
        /// TODO: remove cookies?
        // console.log({deserializeUser: obj})
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
                failureRedirect: '/login?error=true',
                successRedirect: '/profile?success=true',
                // failureFlash: true,
            }),
        )

		const self = this
        const getLoginViewController = (view = 'index', restrict = false) => {
			const restrictedTo = restrict ? ['login'] : undefined
            return this.requestHandler(function loginHandler(subdomain, req, res, host, next) {
                // if (subdomain !== 'login') return next()
                if (view === 'index' && req.isAuthenticated()) return res.redirect('/profile')
                if (view === 'profile' && !req.isAuthenticated()) return res.redirect('/login')

                const credentials = req.user
                const loginData = { credentials, host, appName: self.config.appName, loginUrl: self.getLoginUrl(req, subdomain) }

                return self.renderViewOrTemplate(`login/${view}`, loginData, res)
            }, restrictedTo)
        }
        this.app.get('/', getLoginViewController(undefined, true))
        this.app.get('/login', getLoginViewController())
        this.app.get('/profile', getLoginViewController('profile'))
    }
}
module.exports.module = 'login'
module.exports.description = 'Add the login subdomain controller and user validation methods'
