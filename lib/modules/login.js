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
        const self = this
        this.log.info('adding the login subdomain and controller')
        this.config.subdomains['login'] = this.config.subdomains['login'] || {}
        this.config.subdomains['login'].controller = 'login'

        /// Accept all /login requests
        this.app.post(
            '/login',
            this.requestHandler((subdomain, req, res, host, next) => {
                const isNotLoginSubdomain = subdomain !== 'login'
                if (subdomain === 'login' || isNotLoginSubdomain) return next()
            }),
            passport.authenticate('local', {
                failureRedirect: '/login?error=true',
                successRedirect: '/profile?success=true',
                // failureFlash: true,
            }),
        )

        const logoutHandler = (redirectTo = '/') => {
            return this.requestHandler(function logoutHandler(subdomain, req, res, host, next) {
                req.logout()
                return res.redirect(redirectTo)
            })
        }

        const getLoginViewController = (view = 'index', restrict = false) => {
            return this.requestHandler(function loginHandler(subdomain, req, res, host, next) {
                if (restrict && subdomain !== 'login') return next()
                const loginUrl = self.getLoginUrl(req, subdomain)

                if (view === 'index' && req.isAuthenticated())
                    return res.redirect(`${loginUrl.substr(0, loginUrl.lastIndexOf('/'))}/profile`)
                if (view === 'profile' && !req.isAuthenticated()) return res.redirect(loginUrl)

                const credentials = req.user
                const loginData = {
                    credentials,
                    host,
                    appName: self.config.appName,
                    loginUrl,
                    sso: self.getAvilableSSOProviders(subdomain),
                }

                return self.renderViewOrTemplate(`login/${view}`, loginData, res)
            })
        }
        this.app.get('/', getLoginViewController(undefined, true))
        this.app.get('/login', getLoginViewController())
        this.app.get('/logout', logoutHandler)
        this.app.post('/logout', logoutHandler)
        this.app.get('/profile', getLoginViewController('profile'))
    }
}
module.exports.module = 'login'
module.exports.description = 'Add the login subdomain controller and user validation methods'
