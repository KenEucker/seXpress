/// Begin with the module name
const moduleName = 'login'

/// Name the module init method which is used in logging
function InitLogin(initial, loginOpts = {}) {
    /// dependencies are scoped to the module itself

    this.config.login = this.getCoreOpts(moduleName, loginOpts, initial)

    if (this.config.authentication.enabled || this.config.login.enabled) {
        /// if login is enabled, set up it's routes
        if (this.config.login.enabled) {
            const self = this
            this.log.info(`🤝 adding the login subdomain and controller`)
            this.config.subdomains['login'] = this.config.subdomains['login'] || {}
            this.config.subdomains['login'].controller = 'login'

            const testUserAuth = (req, res, next) => {
                if (self.isValidSubdomain(res.locals.subdomain)) {
                    return this.authenticate('local', res.locals.subdomain)(req, res, next)
                }
                return next()
            }

            const userAuthed = (req, res) => {
                if (self.isAuthenticated(req)) {
                    self.log.status(`👋 user logged in`, {
                        user: req.user,
                        session: req.session,
                        passport: req.session.passport,
                    })

                    /// TODO: send req.uest here so that cookies are saved into redis
                    return res.redirect('/session?success=local')
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
                        const userAuthenticated = self.isAuthenticated(req)

                        if (view === 'index' && userAuthenticated) {
                            const profileUrl = `${
                                loginUrl.indexOf('/login') > loginUrl.indexOf('://') + 2
                                    ? loginUrl.replace('/login', '')
                                    : loginUrl
                            }/profile`

                            return res.redirect(profileUrl)
                        }

                        if (view === 'profile' && !userAuthenticated) {
                            return res.redirect(loginUrl)
                        }

                        const loginData = self.getUserData(req, subdomain)

                        return self.renderTemplateOrView(`login/${view}`, loginData, res)
                    },
                    restrict ? ['login'] : undefined,
                )
            }

            this.app.get('/', getLoginViewController(undefined, true))

            /// TODO: support the option to disable subdomain logins, which forces all users to login.{host} or {host}/login
            // let loginPathController = getLoginViewController()
            // let logoutPathController = getLogoutHandler()
            // let profilePathController = getLoginViewController('profile')

            // if (this.config.login.allowSubdomainLogin) {
            // 	loginPathController = getLoginViewController(undefined, true)
            // 	logoutPathController = getLogoutHandler(undefined, true)
            // 	profilePathController = getLoginViewController('profile', true)
            // }

            this.app.get('/', getLoginViewController(undefined, true))
            this.app.get('/login', getLoginViewController())
            this.app.get('/logout', getLogoutHandler())
            this.app.post('/logout', getLogoutHandler())
            this.app.get('/profile', getLoginViewController('profile'))

            this.registerCoreSubdomain(moduleName)
        }
    }
}

module.exports = InitLogin
module.exports.module = moduleName
module.exports.description = 'Add the login subdomain controller and user validation methods'
module.exports.defaults = false
module.exports.version = '0.0.1'
