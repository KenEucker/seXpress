/// Begin with the module name
const moduleName = 'login'

/// Name the module init method which is used in logging
function InitLogin(initial, loginOpts = {}) {
    /// dependencies are scoped to the module itself
    const passport = require('passport')

    this.config.login = this.getCoreOpts(moduleName, loginOpts, initial)
    /// If authentication is enabled, and login uses authentication, then set up the serialize/deserialize user functions
    if (this.config.authentication.enabled || this.config.login.enabled) {
        const getRequestUserIDFromProvidedUser = (user) => {
            let profile = {}
            let userUniqueID = user.username ? user.username : user.id
            /// TODO: check if provider auth was enabled, if not then how did this happen?

            switch (user.provider) {
                case 'google':
                    profile = {
                        name: user.displayName,
                        email: user.email,
                        picture: user.picture,
                        username: user.given_name,
                    }
                    userUniqueID = user.sub
                    break
                case 'imgur':
                    profile = {
                        name: user.url,
                        email: user.email,
                        picture: null,
                        username: user.url,
                    }
                    userUniqueID = user.id
                    break
                case 'local':
                    break

                default:
                    this.log.error(`cannot serialize user for login provider [${user.provider}]`, {
                        user,
                        profile,
                        userUniqueID,
                    })
                    break
            }

            return profile
        }

        passport.serializeUser((user, done) => {
            console.debug('serializeUser', { user })
            /// TODO: set approrpiate domains for user role
            if (!user) {
                this.log.status(`user not authorized`)
                return process.nextTick(() => {
                    return done(null, false)
                })
            }
            const userID = getRequestUserIDFromProvidedUser(user)

            return process.nextTick(() => {
                return done(null, userID)
            })
        })

        passport.deserializeUser((user, done) => {
            console.debug('deserializeUser', { user })
            /// TODO: remove cookies?
            if (!user) {
                this.log.status(`user not authorized`)
                return process.nextTick(() => {
                    return done(null, false)
                })
            }
            // return process.nextTick(() => {
            return done(null, user)
            // })
        })

        /// if login is enabled, set up it's routes
        if (this.config.login.enabled) {
            const self = this
            this.log.info(`🤝 adding the login subdomain and controller`)
            this.config.subdomains['login'] = this.config.subdomains['login'] || {}
            this.config.subdomains['login'].controller = 'login'

            const testUserAuth = (req, res, next) => {
                if (self.isValidSubdomain(res.locals.subdomain)) {
                    return passport.authenticate('local')(req, res, next)
                }

                cnosole.log('passing')
                return next()
            }

            const userAuthed = (req, res) => {
                if (!!req.isAuthenticated()) {
                    self.log.status(`👋 user logged in`, {
                        user: req.user,
                        session: req.session,
                        passport: req.session.passport,
                    })
                    return res.redirect('/profile?success=local')
                }

                return res.redirect('/login?error=true')
            }

            /// Accept all /login requests
            this.app.post('/login', this.requestHandler(testUserAuth), userAuthed)

            /// Intercept all head post requests on the login subdomain
            this.route(
                '/',
                function loginAuthHandler(req, res) {
                    return testUserAuth(req, res, () => {
                        return userAuthed(req, res)
                    })
                },
                'post',
                undefined,
                ['login'],
            )

            const getLogoutHandler = (redirectTo = '/') => {
                return this.requestHandler(function logoutHandler(req, res) {
                    const user = req.user
                    self.log.status(`🖖 user logged out`, { user })
                    req.logout()

                    return res.redirect(redirectTo)
                })
            }

            const getLoginViewController = (view = 'index', restrict = false) => {
                return this.requestHandler(
                    function loginHandler(req, res, next) {
                        const subdomain = res.locals.subdomain
                        if (restrict && subdomain !== 'login') return next()

                        const loginUrl = self.getLoginUrl(req, subdomain)

                        if (view === 'index' && req.isAuthenticated()) {
                            const profileUrl = `${
                                loginUrl.indexOf('/login') > loginUrl.indexOf('://') + 2
                                    ? loginUrl.replace('/login', '')
                                    : loginUrl
                            }/profile`

                            return res.redirect(profileUrl)
                        }

                        if (view === 'profile' && !req.isAuthenticated()) {
                            return res.redirect(loginUrl)
                        }

                        const loginData = self.getUserData(req, subdomain)

                        return self.renderTemplateOrView(`login/${view}`, loginData, res)
                    },
                    restrict ? ['login'] : undefined,
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
module.exports.version = '0.0.1'
