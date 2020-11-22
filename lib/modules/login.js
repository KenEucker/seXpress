const { red } = require('chalk')
const { response } = require('express')
const passport = require('passport')

const moduleName = 'login'

module.exports = function (loginOpts = {}) {
    this.config.login = this.getCoreOpts(moduleName, loginOpts)

    if (this.config.login.enabled) {
		const getRequestUserFromProvidedUser = (user) => {
            let profile = user

			/// TODO: check if provider auth was enabled, if not then how did this happen?

			switch(user.provider) {
				case 'google':
					profile = { 
						name: user.displayName,
						email: user.email,
						picture: user.picture,
						username: user.given_name,
					}
				break

				default: 
					this.log.error(`cannot deserialize user for login provider [${user.provider}]`, user)
				break
			}

			return profile
		}

        passport.serializeUser((user, done) => {
			/// TODO: set approrpiate domains for user role
			if (!user) {
				this.log.status(`user not authorized`)
				return done(null, false)
			}
			const profile = getRequestUserFromProvidedUser(user)
			console.debug('serializeUser', {profile})
            done(null, profile)
        })

        passport.deserializeUser((user, done) => {
            /// TODO: remove cookies?
			if (!user) {
				this.log.status(`user not authorized`)
				return done(null, false)
			}
			const profile = getRequestUserFromProvidedUser(user)
			console.debug('deserializeUser', {profile})
            done(null, profile)
        })

        if (this.config.authentication.enabled || this.config.login.enabled) {
            const self = this
            this.log.info(`🤝 adding the login subdomain and controller`)
            this.config.subdomains['login'] = this.config.subdomains['login'] || {}
            this.config.subdomains['login'].controller = 'login'

            const testUserAuth = (subdomain, req, res, host, next) => {
                if (this.isValidSubdomain(subdomain)) {
                    return passport.authenticate('local')(req, res, next)
                }

                return next()
            }

            const userAuthed = (req, res) => {
                if (!!req.isAuthenticated()) {
                    self.log.status(`👋 user logged in`, { user: req.user })
                    return res.redirect('/profile?success=local')
                }

                return res.redirect('/login?error=true')
            }
            /// Accept all /login requests
            this.app.post('/login', this.requestHandler(testUserAuth), userAuthed)

            /// Intercept all head post requests on the login subdomain
            this.route(
                '/',
                (subdomain, req, res, host, next) => {
                    return testUserAuth(subdomain, req, res, host, () => {
                        return userAuthed(req, res)
                    })
                },
                'post',
                ['login'],
            )

            const getLogoutHandler = (redirectTo = '/') => {
                return this.requestHandler(function logoutHandler(subdomain, req, res, host, next) {
                    const user = req.user
                    self.log.status(`🖖 user logged out`, { user })
                    req.logout()
                    // user.google.token = undefined
                    // user.reddit.token = undefined
                    // user.imgur.token = undefined
                    // return user.save(function(err) {
                    // 	res.redirect(redirectTo)
                    // })
                    return res.redirect(redirectTo)
                })
            }

            const getLoginViewController = (view = 'index', restrict = false) => {
                return this.requestHandler(function loginHandler(subdomain, req, res, host, next) {
                    if (restrict && subdomain !== 'login') return next()
                    const loginUrl = self.getLoginUrl(req, subdomain)

                    if (view === 'index' && req.isAuthenticated())
                        return res.redirect(
                            `${loginUrl.substr(0, loginUrl.lastIndexOf('/'))}/profile`,
                        )
                    if (view === 'profile' && !req.isAuthenticated()) return res.redirect(loginUrl)

                    const loginData = self.getUserData(req, subdomain)

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
}
module.exports.module = moduleName
module.exports.description = 'Add the login subdomain controller and user validation methods'
