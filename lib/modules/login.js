const passport = require('passport')

const moduleName = 'login'

function InitLogin(initial, loginOpts = {}) {
    this.config.login = this.getCoreOpts(moduleName, loginOpts, initial)

    /// If authentication is enabled, and login uses authentication, then set up the serialize/deserialize user functions
    if (this.config.authentication.enabled || this.config.login.enabled) {
        const getRequestUserFromProvidedUser = (user, de = false) => {
            let profile = user

            /// TODO: check if provider auth was enabled, if not then how did this happen?

            switch (user.provider) {
                case 'google':
                    profile = {
                        name: user.displayName,
                        email: user.email,
                        picture: user.picture,
                        username: user.given_name,
                    }
                    break
                case 'local':
                    break

                default:
                    this.log.error(
                        `cannot deserialize user for login provider [${user.provider}]`,
                        user,
                    )
                    break
            }

            return profile
        }

        passport.serializeUser((user, done) => {
            console.debug('serializeUser', { user })
            /// TODO: set approrpiate domains for user role
            if (!user) {
                this.log.status(`user not authorized`)
                return done(null, false)
            }
            const profile = getRequestUserFromProvidedUser(user)

            return done(null, profile)
        })

        passport.deserializeUser((user, done) => {
            console.debug('deserializeUser', { user })
            /// TODO: remove cookies?
            if (!user) {
                this.log.status(`user not authorized`)
                return done(null, false)
            }

            return done(null, user)
        })

        /// if login is enabled, set up it's routes
        if (this.config.login.enabled) {
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
                    console.log('redirecting getLogoutHandler')

                    return res.redirect(redirectTo)
                })
            }

            const getLoginViewController = (view = 'index', restrict = false) => {
                return this.requestHandler(
                    function loginHandler(subdomain, req, res, host, next) {
                        if (restrict && subdomain !== 'login') return next()
                        const loginUrl = self.getLoginUrl(req, subdomain)

                        if (view === 'index' && req.isAuthenticated()) {
                            const profileUrl = `${loginUrl.substr(
                                0,
                                loginUrl.lastIndexOf('/'),
                            )}/profile`
                            console.log({ profileUrl, loginUrl })
                            console.log('redirecting getLoginViewController')
                            return res.redirect(profileUrl)
                        }
                        if (view === 'profile' && !req.isAuthenticated()) {
                            console.log('redirecting getLoginViewController')

                            return res.redirect(loginUrl)
                        }

                        const loginData = self.getUserData(req, subdomain)

                        return self.renderViewOrTemplate(`login/${view}`, loginData, res)
                    },
                    undefined,
                    restrict,
                )
            }
            this.app.get('/', getLoginViewController(undefined, true))
            this.app.get('/login', getLoginViewController())
            this.app.get('/logout', getLogoutHandler())
            this.app.post('/logout', getLogoutHandler())
            this.app.get('/profile', getLoginViewController('profile'))
        }
    }
}

module.exports = InitLogin
module.exports.module = moduleName
module.exports.description = 'Add the login subdomain controller and user validation methods'
module.exports.defaults = false
module.exports.version = "0.0.1"
