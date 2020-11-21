const { red } = require('chalk')
const { response } = require('express')
const passport = require('passport')

const moduleName = 'login'

module.exports = function (loginOpts = {}) {
    this.config.login = this.getCoreOpts(moduleName, loginOpts, {})

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

    if (this.config.authentication.enabled || this.config.login.enabled) {
        const self = this
        this.log.info(`🤝	adding the login subdomain and controller`)
        this.config.subdomains['login'] = this.config.subdomains['login'] || {}
        this.config.subdomains['login'].controller = 'login'

        /// Accept all /login requests
        this.app.post(
            '/login',
            this.requestHandler((subdomain, req, res, host, next) => {
				if (this.isValidSubdomain(subdomain)) {
					return passport.authenticate('local')(req, res, next)
				}

				return next()
			}), (req, res) => {
				if (!!req.user) {
					self.log.status(`👋 user logged in`, { user: req.user })
					return res.redirect('/profile?success=local')
				}

				return res.redirect('/login?error=true')
			})

        const getLogoutHandler = (redirectTo = '/') => {
            return this.requestHandler(function logoutHandler(subdomain, req, res, host, next) {
				self.log.status(`🖖 user logged out`)
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
        this.app.get('/logout', getLogoutHandler())
        this.app.post('/logout', getLogoutHandler())
        this.app.get('/profile', getLoginViewController('profile'))
    }
}
module.exports.module = moduleName
module.exports.description = 'Add the login subdomain controller and user validation methods'
