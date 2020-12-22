/// Begin with the module name
const moduleName = 'authentication'

/// Name the module init method which is used in logging
function InitAuthentication(initial, authenticationOps = {}) {
    /// dependencies are scoped to the module itself
    const { use: refresh, requestNewAccessToken } = require('passport-oauth2-refresh')
    const uest = require('uest')
    const crypto = require('crypto')
    const {
        setInterval,
        getSubdomainPrefix,
        consoleLogEmojiNumber,
        merge,
		getValuesFromObjectOrDefault,
		getFromQueryOrPathOrBody,
    } = this.middlewares.util

    const { BasicStrategy } = require('passport-http')
    const { Strategy: CookieStrategy } = require('passport-cookie')
    const { Strategy: LocalStrategy } = require('passport-local')
    const { Strategy: ImgurStrategy } = require('passport-imgur')
    const { Strategy: RedditStrategy } = require('passport-reddit')
    const { Strategy: GitHubStrategy } = require('passport-github')
    const { Strategy: InstagramStrategy } = require('passport-instagram')
    const { Strategy: GoogleStrategy } = require('passport-google-oauth2')
    const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt')

    /*
		Note: This is where we set up application-wide api authentication. We are
		checking the defaults for these api values when we should be checking a "keys"
		or "api" option, that overrides whenever a subdomain configurationdoes not have
		these values set.
	*/

    /// TODO: put this somewhere more approrpiate
    this.app.use(uest())

    this.config.authentication = this.getCoreOpts(moduleName, authenticationOps, initial)
    this.authTokens.default = this.config.authentication

    const authsInitialized = []

    const getInitializedPassport = () => {
        const passport = require('passport')

        /// Initialize passportjs
        if (this.config.authentication && this.config.authentication.enabled) {
            this.log.debug(moduleName, `initializing passportjs for the authentication module`, {
                passport: this.config.authentication.passport,
                session: this.config.authentication.passport.session,
            })
            this.app.use(passport.initialize(this.config.authentication.passport))
            this.app.use(passport.session(this.config.authentication.passport.session))
        }

        return passport
    }

    const loginPassport = getInitializedPassport()

    /// TODO: get list of domains to authenticate from the config and use only those

    /// TODO: generate uuid hashes for all authenticated users against the application secret,
    /// TODO: uuid hashes to be used in nonce validation as well

    /// If security is enabled, set up basic authentication
    if (this.config.authentication.enabled) {
        const allSchemes = ['local', 'basic', 'jwt', 'cookie']
        const schemes = this.config.authentication.schemes || allSchemes
        const noValidator = function NONE(u, p, d) {
            d('no validation method set')
        }

        schemes.forEach((scheme) => {
            scheme =
                typeof scheme === 'object'
                    ? scheme
                    : {
                          name: scheme,
                      }
            let logMessage = `🔑 setting [${scheme.name}] auth strategy`

            switch (scheme.name) {
                case 'local':
                    const localOpts = merge(
                        {
                            usernameField: scheme.usernameField || 'username',
                            passwordField: scheme.passwordField || 'password',
                        },
                        scheme,
                    )

                    scheme.credentials =
                        scheme.credentials || this.config.authentication.credentials
                    const localUsername = scheme.credentials ? scheme.credentials.username : null
                    const localPassword = scheme.credentials ? scheme.credentials.password : null

                    const localValidator = (u, p, d) => {
                        const usernamePassed = !!localUsername
                            ? RegExp(localUsername).test(u)
                            : true
                        const passwordPassed = !!localPassword
                            ? RegExp(localPassword).test(p)
                            : true

                        this.log.debug(moduleName, '[Local Auth] attempt', {
                            usernamePassed,
                            passwordPassed,
                            credentials: scheme.credentials,
                            u,
                            p,
                        })

                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }

                        return d(null, false)
                    }

                    const localOrError = scheme.credentials ? localValidator : noValidator
                    scheme.validateUser = !!scheme.validateUser ? scheme.validateUser : localOrError

                    loginPassport.use(new LocalStrategy(localOpts, scheme.validateUser))
                    authsInitialized.push({ internal: 'local', credentials: scheme.credentials })
                    break

                case 'cookie':
                    const cookieOpts = merge(
                        {
                            cookieName: this.config.name,
                            signed: true,
                            passReqToCallback: true,
                        },
                        scheme,
                    )
                    const cookieValidator = (u, p, d) => {
                        const usernamePassed = !!localUsername
                            ? RegExp(localUsername).test(u)
                            : true
                        const passwordPassed = !!localPassword
                            ? RegExp(localPassword).test(p)
                            : true
                        this.log.debug(moduleName, '[Cookie Auth] attempt', {
                            jwt_payload: p,
                            scheme,
                        })

                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }
                        return d(null, false)
                    }
                    /// Always use the cookie validator here, cookies are set globally to the app
                    scheme.validateUser = !!scheme.validateUser
                        ? scheme.validateUser
                        : cookieValidator

                    loginPassport.use(new CookieStrategy(cookieOpts, cookieValidator))
                    authsInitialized.push({ internal: 'cookie', name: cookieOpts.cookieName })
                    break

                case 'basic':
                    scheme.credentials =
                        scheme.credentials || this.config.authentication.credentials

                    const basicUsername = scheme.credentials ? scheme.credentials.username : null
                    const basicPassword = scheme.credentials ? scheme.credentials.password : null

                    const basicValidator = (u, p, d) => {
                        const usernamePassed = !!basicUsername
                            ? RegExp(basicUsername).test(u)
                            : true
                        const passwordPassed = !!basicPassword
                            ? RegExp(basicPassword).test(p)
                            : true

                        this.log.debug(moduleName, '[Basic Auth] attempt', {
                            usernamePassed,
                            passwordPassed,
                            credentials: scheme.credentials,
                            u,
                            p,
                        })
                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }

                        return d(null, false)
                    }
                    const basicOrError = scheme.credentials ? basicValidator : noValidator
                    scheme.validateUser = !!scheme.validateUser ? scheme.validateUser : basicOrError

                    loginPassport.use(new BasicStrategy(scheme.validateUser))
                    authsInitialized.push({ internal: 'basic', credentials: scheme.credentials })
                    break

                case 'jwt':
                    const jwtOpts = merge(
                        {
                            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), //ExtractJwt.fromAuthHeaderWithScheme('JWT'),
                            secretOrKey: scheme.credentials
                                ? scheme.credentials.secret
                                : this.config.authentication.secret,
                            passReqToCallback: true,
                            authScheme: 'JWT',
                            // issuer: this.config.host,
                            // audience: this.config.host,
                        },
                        scheme,
                    )

                    const jwtValidator = (r, p, d) => {
                        this.log.debug(moduleName, '[JWT Auth] attempt', { jwt_payload: p, scheme })

                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }

                        return d(null, false)
                    }
                    const jwtOrError = scheme.credentials ? jwtValidator : noValidator
                    scheme.validateUser = !!scheme.validateUser ? scheme.validateUser : jwtOrError

                    loginPassport.use(new JwtStrategy(jwtOpts, scheme.validateUser))
                    authsInitialized.push({ internal: 'jwt', secret: jwtOpts.secretOrKey })
                    break

                default:
                    logMessage = 'scheme not supported for API'
                    break
            }

            this.log.debug(moduleName, logMessage, scheme)
        })
    }

    /// Configure third party oauth providers
    const configurePassportMiddleware = (
        securityOpts = { scope: ['email'] },
        middlewareName,
        middlewareConfigName,
        authStrategyMethod,
        profileMatcher = () => false,
        keys,
        customCallback,
        customAuthCallback,
    ) => {
        if (!authStrategyMethod) return

        /// TODO: SHARE AUTH ACROSS PASSPORTS
        const middlewarePassport = getInitializedPassport()

        /// Setup
        middlewareConfigName = middlewareConfigName || middlewareName
        keys = keys || {
            clientID: `${middlewareName}ClientID`,
            clientSecret: `${middlewareName}ClientSecret`,
            callbackURL: `${middlewareName}CallbackURL`,
            apiKey: `${middlewareName}ApiKey`,
            username: `${middlewareName}Username`,
            password: `${middlewareName}Password`,
            emailAddress: `${middlewareName}EmailAddress`,
            userAgent: `${middlewareName}UserAgent`,
            profile: `${middlewareName}Profile`,
            authorization: `${middlewareName}Authorization`,
            accessToken: `${middlewareName}AccessToken`,
            refreshToken: `${middlewareName}RefreshToken`,
        }

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
                case 'reddit':
                    profile = {
                        name: user.name,
                        // email: user.email,
                        picture: user.icon_image,
                        username: user.name,
                    }
                    userUniqueID = user.name
                    break
                case 'github':
                    profile = {
                        name: user.login,
                        // email: user.email,
                        picture: user.avatar_url,
                        username: user.username,
                    }
                    userUniqueID = user.login
                    break
                case 'local':
                    profile.username = profile.name = userUniqueID = user.username
                    break

                default:
                    this.log.error(`cannot serialize user for login provider [${user.provider}]`, {
                        user,
                        profile,
                        userUniqueID,
                    })
                    break
            }
            profile.id = userUniqueID

            return profile
        }

        middlewarePassport.serializeUser((user, done) => {
            // console.debug('serializeUser', { user })
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

        middlewarePassport.deserializeUser((user, done) => {
            // console.debug('deserializeUser', { user })
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

        const setTokensForSubdomain = (subdomain, accessToken, refreshToken, profile) => {
			const currentTokens = this.authTokens[subdomain][middlewareConfigName]
            if (profileMatcher(profile, subdomain, currentTokens)) {
                this.authTokens[subdomain][middlewareConfigName][keys.accessToken] = accessToken
                this.authTokens[subdomain][middlewareConfigName][keys.refreshToken] =
                    currentTokens[keys.refreshToken] || refreshToken
                // this.authTokens[subdomain][middlewareConfigName][keys.profile] =
                //     currentTokens[keys.profile] || profile

                this.log.status(
                    `setting ${middlewareConfigName} authentication information for subdomain: ${subdomain}`,
                    this.authTokens[subdomain][middlewareConfigName],
                )

                return true
            }

            return false
        }

        /// Deprecated function
        const setTokens = (accessToken, refreshToken, profile, subdomain) => {
            const profilesMatched = []
            const subdomainsToSet = subdomain ? [subdomain] : Object.keys(this.config.subdomains)

            /// Set tokens for these subdomains that match with the profile
            for (const sub of subdomainsToSet) {
                if (this.authTokens[sub] && Object.keys(this.authTokens[sub]).length) {
                    if (setTokensForSubdomain(sub, accessToken, refreshToken, profile)) {
                        profilesMatched.push(profile)
                    }
                }
            }

            return profilesMatched
        }

        const attemptToAuthorizeForSubdomains = (req, accessToken, refreshToken, profile, done, manual = false) => {
            const subdomain = getSubdomainPrefix(this.config, req)
            // const profilesMatched = setTokens(
            //     accessToken,
            //     refreshToken,
            //     profile,
            //     subdomain !== 'index' ? subdomain : null,
            // )
            console.log('attemptToAuthorizeForSubdomains', {
                subdomain,
                accessToken,
                refreshToken,
                profile,
            })
            if (subdomain === 'index' && !manual) {
                const subdomainsToSet = Object.keys(this.config.subdomains).filter(
                    (s) => s !== 'index',
                )
                console.log(`sending auth callback to all subdomains configured for auth`, {
                    subdomainsToSet,
                })
                for (const sub of subdomainsToSet) {
                    const queryString = Object.keys(req.query)
                        .reduce((o, k) => {
                            o = `${o}&${k}=${req.query[k]}`
                            return o
                        }, '')
                        .substring(1)
					const subdomainCallbackUrl = `${this.authTokens[sub][middlewareConfigName].opts.callbackURL}?${queryString}`
					const requestBaseUrl = `${this.getBaseUrl(undefined, undefined, sub)}/`
					
                    req.uest(
                        {
                            method: 'POST',
                            url: subdomainCallbackUrl,
                            baseUrl: requestBaseUrl,
                            body: {accessToken, refreshToken, profile}
                        },
                        (err, res, body) => {
                            // console.log('HELLLOOOOO', {
                            //     sub,
                            //     middlewareConfigName,
                            //     subdomainCallbackUrl,
                            //     err,
							// })
							
                            if (err) {
                                console.log({ err })
                                return
                            }

                            // console.log('User-session created for', body.user)

                            // `req.session` is up-to-date
                            // console.log(`Welcome back ${req.session.user}!`)

                            // res.redirect('/profile')
                        },
                    )
				}
            }

            if (setTokensForSubdomain(subdomain, accessToken, refreshToken, profile)) {
                this.log.status(
                    `user authenticated via third party auth [${middlewareConfigName}]`,
                    {
                        profile,
                        accessToken,
                        refreshToken,
                    },
                )

                // return process.nextTick(() => {
                return done(null, profile)
                // })
            }

            /// Someone else wants to authorize our app? Why?
            this.log.error('Someone else wants to authorize our app? Why?', {
                auth: middlewareConfigName,
                profile,
            })

            /// Do not authenticate this user
            // return process.nextTick(() => {
            return done(null, false)
            // })
        }

        const subdomainGetTokenRequest = (req, res) => {
            if (this.isValidRequestOrigin(req)) {
                const response = {}
                const { subdomain } = res.locals
                const subdomainAuth = this.authTokens[subdomain][middlewareConfigName]

                // response[keys.clientAuthorization] = subdomainAuth[keys.clientAuthorization]
                // response[keys.refreshToken] = subdomainAuth[keys.refreshToken]
                response[keys.accessToken] = subdomainAuth[keys.accessToken]

                this.log.debug(moduleName, `${middlewareConfigName} getToken response`, {
                    subdomain,
                    subdomainAuth,
                    apiResponse: response,
                })

                // This will only return the access token if the request is coming from the site itself
                return res.json(response)
            }

            return res.status(401).end()
        }

        const convertAuthOptsToStrategyOpts = (authOpts, defaults) => {
            const _defaults = {
                passReqToCallback: true,
                scope: authOpts.scope ? authOpts.scope : securityOpts.scope,
                clientID: authOpts[keys.clientID] || null,
                clientSecret: authOpts[keys.clientSecret] || null,
                apiKey: authOpts[keys.apiKey] || null,
                emailAddress: authOpts[keys.emailAddress] || null,
                username: authOpts[keys.username] || null,
                password: authOpts[keys.password] || null,
                userAgent: (authOpts[keys.userAgent] || '')
                    .replace('VERSION', this.config.version)
                    .replace('URL', this.getBaseUrl()),
                callbackURL: authOpts[keys.callbackURL] || `/auth/${middlewareConfigName}/callback`,
                authorization: authOpts[keys.authorization] || null,
                accessToken: authOpts[keys.accessToken] || null,
                refreshToken: authOpts[keys.refreshToken] || null,
            }

            const strategyOpts = getValuesFromObjectOrDefault(
                Object.keys(_defaults),
                _defaults,
                defaults,
            )

            return strategyOpts
        }

        const defaultStrategyOpts = convertAuthOptsToStrategyOpts(
            this.authTokens.default[middlewareConfigName] ||
                this.authTokens.default[middlewareName],
            securityOpts[middlewareConfigName] || securityOpts[middlewareName],
        )
        const uniqueClientStrategies = []
        uniqueClientStrategies[defaultStrategyOpts.clientID] = 'default'

        /// Set the default opts
        this.authTokens.default[middlewareConfigName] = this.authTokens.default[
            middlewareConfigName
        ]
            ? this.authTokens.default[middlewareConfigName]
            : defaultStrategyOpts

        /// Set the per subdomain opts
        for (const subdomain of Object.keys(this.config.subdomains)) {
            const subdomainMiddlewareOpts = this.config.subdomains[subdomain][middlewareConfigName]
                ? this.config.subdomains[subdomain][middlewareConfigName]
                : this.config.subdomains[subdomain][middlewareName] || {}

            this.authTokens[subdomain][middlewareConfigName] = {}

            /// TODO: set per subdomain strategyOps overrides
            const subdomainStrategyOpts = convertAuthOptsToStrategyOpts(
                subdomainMiddlewareOpts,
                defaultStrategyOpts,
            )
            const subdomainClientID = subdomainStrategyOpts.clientID

            if (subdomainClientID) {
                /// If this is a client ID we've not set before, then we need to set up a unique strategy for it
                if (Object.keys(uniqueClientStrategies).indexOf(subdomainClientID) === -1) {
                    this.log.debug(moduleName, `New ClientID for auth strategy discovered`, {
                        auth: middlewareName,
                        subdomainClientID,
                    })
                    uniqueClientStrategies[subdomainClientID] = [subdomain]
                } else if (uniqueClientStrategies[subdomainClientID] !== 'default') {
                    uniqueClientStrategies[subdomainClientID].push(subdomain)
                }

                this.authTokens[subdomain][middlewareConfigName].opts = subdomainStrategyOpts
            }
        }

        /// configure per client auth strategies
        for (const clientID of Object.keys(uniqueClientStrategies)) {
            const validSubdomainsIsString = typeof uniqueClientStrategies[clientID] === 'string'
            const validSubdomains = validSubdomainsIsString
                ? [uniqueClientStrategies[clientID]]
                : uniqueClientStrategies[clientID]
            const firstSubdomainSet = validSubdomains[0]
            const subdomainIsDefault = firstSubdomainSet === 'default'
            const uniqueClientStrategyOpts = subdomainIsDefault
                ? this.authTokens[firstSubdomainSet][middlewareConfigName]
                : this.authTokens[firstSubdomainSet][middlewareConfigName].opts
            const authStrategyOpts = convertAuthOptsToStrategyOpts(
                uniqueClientStrategyOpts,
                defaultStrategyOpts,
            )

            const authStrategy = new authStrategyMethod(
                authStrategyOpts,
                attemptToAuthorizeForSubdomains,
            )

            middlewarePassport.use(middlewareConfigName, authStrategy)
            refresh(middlewareConfigName, authStrategy)

            const interceptSubdomains =
                validSubdomains.indexOf('default') !== -1 ? [] : interceptSubdomains

            if (typeof customCallback === 'function') {
                /// These are the only custom things for a given strategy
                this.app.get(
                    `/auth/${middlewareConfigName}`,
                    this.requestHandler((req, res, next) => {
                        return next()
                    }, interceptSubdomains),
                    (req, res, next) => {
                        return customCallback(req, res, next, {
                            middlewarePassport,
                            middlewareConfigName,
                            scope: authStrategyOpts.scope,
                        })
                    },
                )
            } else {
                /// These are the only custom things for a given strategy
                this.app.get(
                    `/auth/${middlewareConfigName}`,
                    this.requestHandler((req, res, next) => {
                        return next()
                    }, interceptSubdomains),
                    middlewarePassport.authenticate(middlewareConfigName, authStrategyOpts.scope),
                    // 'get',
                    // interceptSubdomains,
                )
            }

            const successRedirect = securityOpts.successRedirect
                ? securityOpts.successRedirect
                : `/profile?success=${middlewareConfigName}`
            const failureRedirect = securityOpts.successRedirect
                ? securityOpts.successRedirect
                : `/login?error=${middlewareConfigName}`

            if (typeof customAuthCallback === 'function') {
                this.app.get(
                    authStrategyOpts.callbackURL,
                    this.requestHandler((req, res, next) => {
                        return customAuthCallback(req, res, next, {
                            successRedirect,
                            failureRedirect,
                            middlewareConfigName,
                            middlewarePassport,
                        })
                    }),
                )
            } else {
                this.app.get(
                    authStrategyOpts.callbackURL,
                    middlewarePassport.authenticate(middlewareConfigName, {
                        successRedirect,
                        failureRedirect,
                    }),
                    // 'get',
                    // false,
                    // interceptSubdomains,
                )
			}
			/// TODO: recieve a post request on the callbackURL to be able to propogate auth across subdomains
			this.app.post(
				authStrategyOpts.callbackURL,
				(req, res, next) => {
					const { subdomain, host } = res.locals

					const code = getFromQueryOrPathOrBody(req, 'code')

					if (!code) {
						const errorMessage = 'callback cannot be called from just anyone'
						this.log.error(errorMessage, {subdomain, middlewareConfigName, code,})
						return res.json({errorMessage})
					}

					const accessToken = getFromQueryOrPathOrBody(req, 'accessToken')
					const refreshToken = getFromQueryOrPathOrBody(req, 'refreshToken')
					const profile = getFromQueryOrPathOrBody(req, 'profile')

					return attemptToAuthorizeForSubdomains(req, accessToken, refreshToken, profile, (error, userID) => {
						return res.json({error, userID})
					}, true)

				},
			)

            /// TODO: allow for a custom callback method here, per strategy per subdomain

            /// Only allow getToken requests on non-core subdomain requests
            this.route(
                `/auth/${middlewareConfigName}/getToken`,
                subdomainGetTokenRequest,
                ['get', 'post'],
                undefined,
                interceptSubdomains,
            )

            this.log.debug(
                moduleName,
                `auth strategy [${middlewareConfigName}] created for client ID:`,
                {
                    clientID: authStrategyOpts.clientID,
                    scope: authStrategyOpts.scope,
                },
            )

            authsInitialized.push({
                external: middlewareName,
                clientID: authStrategyOpts.clientID,
            })
        }

        const refreshFrequency = securityOpts.refreshFrequency || 29 * (1000 * 60 * 60 * 24) // 29 days
        const refreshTokens = () => {
            const refreshToken = (subdomain) => {
                const theRefreshTokenToUse = this.authTokens[subdomain][middlewareName][
                    keys.refreshToken
                ]
                this.log.status(
                    `attempting to refresh ${middlewareName} access token using the refresh token`,
                    {
                        key: keys.refreshToken,
                        token: theRefreshTokenToUse,
                    },
                )
                requestNewAccessToken(
                    middlewareName,
                    theRefreshTokenToUse,
                    (err, accessToken, refreshToken) => {
                        this.log.status(`${middlewareName} access token has been refreshed`, {
                            refreshToken,
                            middlewareName,
                        })
                        /// TODO: FIX THIS, this won't work
                        setTokens(accessToken, refreshToken, null)
                    },
                )
            }

            for (const subdomain of Object.keys(this.config.subdomains)) {
                if (authTokens[subdomain] && Object.keys(authTokens[subdomain]).length) {
                    refreshToken(subdomain)
                }
            }
        }
        setInterval(refreshTokens, refreshFrequency)

        /// Save the defaults back to the authTokens
        this.authTokens.default[middlewareConfigName] = defaultStrategyOpts
    }

    const authenticationStrategies = Object.keys(this.config.authentication)

    /// TODO: turn this into a imgurAPIModule
    if (this.config.authentication.imgur && this.config.authentication.imgur.imgurClientID) {
        const imgurAuthPrefix = 'imgur'
        const imgurUserValidator =
            typeof this.config.authentication.imgur.imgurUserValidator === 'function'
                ? this.config.authentication.imgur.imgurUserValidator
                : (profile, subdomain, authTokens) => {
                      if (authTokens.opts.emailAddress)
                          return (
                              profile !== null &&
                              profile.email.toLocaleLowerCase() ===
                                  authTokens.opts.emailAddress.toLocaleLowerCase()
                          )
                      if (authTokens.opts.username)
                          return (
                              profile !== null &&
                              profile.url.toLocaleLowerCase() ===
                                  authTokens.opts.username.toLocaleLowerCase()
                          )

                      return false
                  }
        authenticationStrategies.forEach((strategyConfigName) => {
            if (strategyConfigName.indexOf(imgurAuthPrefix) === 0) {
                configurePassportMiddleware(
                    this.config.authentication,
                    imgurAuthPrefix,
                    strategyConfigName,
                    ImgurStrategy,
                    imgurUserValidator,
                )
            }
        })
    } else {
        this.app.get('/auth/imgur/*', (req, res) => {
            return res.send("I don't have any imgur apis set in my configuration")
        })
    }

    /// TODO: send this method to the redditAPIModule middleware
    if (this.config.authentication.reddit && this.config.authentication.reddit.redditClientID) {
        const redditAuthPrefix = 'reddit'
        const redditUserValidator =
            typeof this.config.authentication.reddit.redditUserValidator === 'function'
                ? this.config.authentication.reddit.redditUserValidator
                : (profile, subdomain, authTokens) => {
                      console.log({ profile, subdomain, authTokens, authTokens })
                      if (authTokens.opts.username)
                          return (
                              profile !== null &&
                              profile.name.toLocaleLowerCase() ===
                                  authTokens.opts.username.toLocaleLowerCase()
                          )

                      return false
                  }
        authenticationStrategies.forEach((strategyConfigName) => {
            if (strategyConfigName.indexOf(redditAuthPrefix) === 0) {
                configurePassportMiddleware(
                    Object.assign(this.config.authentication, { scope: ['identity'] }),
                    redditAuthPrefix,
                    strategyConfigName,
                    RedditStrategy,
                    redditUserValidator,
                    undefined,
                    (req, res, next, opts = {}) => {
                        const { subdomain } = res.locals
                        const sessionState = crypto.randomBytes(32).toString('hex')
                        this.authTokens[subdomain][
                            strategyConfigName
                        ].state = req.session.state = sessionState

                        if (subdomain === 'index') {
                            Object.keys(this.config.subdomains).forEach((sub) => {
                                if (
                                    this.authTokens[sub] &&
                                    this.authTokens[sub][strategyConfigName]
                                ) {
                                    // console.log('setting state for', {sub, strategyConfigName, sessionState})
                                    this.authTokens[sub][strategyConfigName].state = sessionState
                                }
                            })
                        }

                        return opts.middlewarePassport.authenticate(
                            opts.middlewareConfigName,
                            merge(opts.authStrategyOpts, {
                                state: req.session.state,
                                duration: 'permanent',
                            }),
                        )(req, res, next)
                    },
                    (req, res, next, opts = {}) => {
                        const { subdomain } = res.locals
                        const stateFromIndexRequest =
                            this.authTokens[subdomain] &&
                            this.authTokens[subdomain][opts.middlewareConfigName]
                                ? this.authTokens[subdomain][opts.middlewareConfigName].state
                                : undefined
                        if (
                            req.query.state == req.session.state ||
                            (stateFromIndexRequest && req.query.state === stateFromIndexRequest)
                        ) {
                            // console.log({subdomain, middlewareConfigName: opts.middlewareConfigName})
                            return opts.middlewarePassport.authenticate(opts.middlewareConfigName, {
                                successRedirect: opts.successRedirect,
                                failureRedirect: opts.failureRedirect,
                            })(req, res, next)
                        } else {
                            return next(new Error(403))
                        }
                    },
                )
            }
        })
    } else {
        this.app.get('/auth/reddit/*', (req, res) => {
            const responseMessage = "I don't have any reddit apis set in my configuration"
            res.send(responseMessage)
        })
    }

    /// TODO: turn this into a googleAPIModule
    if (this.config.authentication.google && this.config.authentication.google.googleClientID) {
        const googleAuthPrefix = 'google'
        const googleUserValidator =
            typeof this.config.authentication.google.googleUserValidator === 'function'
                ? this.config.authentication.google.googleUserValidator
                : (profile, subdomain, authTokens) => {
                      // console.log({ googleProfile: profile, authTokens, subdomain })
                      if (authTokens.opts.emailAddress)
                          return (
                              profile !== null &&
                              profile.username.toLocaleLowerCase() ===
                                  authTokens.opts.emailAddress.toLocaleLowerCase()
                          )
                      if (authTokens.opts.username)
                          return (
                              profile !== null &&
                              profile.username.toLocaleLowerCase() ===
                                  authTokens.opts.username.toLocaleLowerCase()
                          )

                      return false
                  }
        authenticationStrategies.forEach((strategyConfigName) => {
            if (strategyConfigName.indexOf(googleAuthPrefix) === 0) {
                configurePassportMiddleware(
                    Object.assign(this.config.authentication, { scope: ['email', 'profile'] }),
                    googleAuthPrefix,
                    strategyConfigName,
                    GoogleStrategy,
                    googleUserValidator,
                )
            }
        })
    } else {
        this.app.get('/auth/google/*', (req, res) => {
            const responseMessage = "I don't have any google apis set in my configuration"
            res.status(404).send(responseMessage)
        })
    }

    /// TODO: turn this into a githubAPIModule
    if (this.config.authentication.github && this.config.authentication.github.githubClientID) {
        const githubAuthPrefix = 'github'
        const githubUserValidator =
            typeof this.config.authentication.github.githubUserValidator === 'function'
                ? this.config.authentication.github.githubUserValidator
                : (profile, subdomain, authTokens) => {
                      if (authTokens.opts.username)
                          return (
                              profile !== null &&
                              profile.login.toLocaleLowerCase() ===
                                  authTokens.opts.username.toLocaleLowerCase()
                          )

                      return false
                  }
        authenticationStrategies.forEach((strategyConfigName) => {
            if (strategyConfigName.indexOf(githubAuthPrefix) === 0) {
                configurePassportMiddleware(
                    Object.assign(this.config.authentication, { scope: ['email', 'profile'] }),
                    githubAuthPrefix,
                    strategyConfigName,
                    GitHubStrategy,
                    githubUserValidator,
                )
            }
        })
    } else {
        this.app.get('/auth/github/*', (req, res) => {
            const responseMessage = "I don't have any github apis set in my configuration"
            res.status(404).send(responseMessage)
        })
    }

    /// TODO: turn this into a instagramAPIModule
    if (
        this.config.authentication.instagram &&
        this.config.authentication.instagram.instagramClientID
    ) {
        const instagramAuthPrefix = 'instagram'
        const instagramUserValidator =
            typeof this.config.authentication.instagram.instagramUserValidator === 'function'
                ? this.config.authentication.instagram.instagramUserValidator
                : (profile, subdomain, authTokens) => {
                      // console.log({ googleProfile: profile, authTokens, subdomain })
                      if (authTokens.opts.instagramEmailAddress)
                          return (
                              profile !== null &&
                              profile.username.toLocaleLowerCase() ===
                                  authTokens.opts.instagramEmailAddress.toLocaleLowerCase()
                          )
                      if (authTokens.opts.username)
                          return (
                              profile !== null &&
                              profile.username.toLocaleLowerCase() ===
                                  authTokens.opts.username.toLocaleLowerCase()
                          )

                      return false
                  }
        authenticationStrategies.forEach((strategyConfigName) => {
            if (strategyConfigName.indexOf(instagramAuthPrefix) === 0) {
                configurePassportMiddleware(
                    Object.assign(this.config.authentication, { scope: ['email', 'profile'] }),
                    instagramAuthPrefix,
                    strategyConfigName,
                    InstagramStrategy,
                    instagramUserValidator,
                )
            }
        })
    } else {
        this.app.get('/auth/instagram/*', (req, res) => {
            const responseMessage = "I don't have any instagram apis set in my configuration"
            res.status(404).send(responseMessage)
        })
    }

    if (authsInitialized.length) {
        this.log.info(
            `🗝  authorization providers have been initialized ${consoleLogEmojiNumber(
                authsInitialized.length,
            )}`,
            this.config.debug ? authsInitialized : undefined,
        )
    }
}

module.exports = InitAuthentication
module.exports.module = moduleName
module.exports.description = 'Handles OATH requests for authenticating with third-party APIs'
module.exports.defaults = {
    enabled: false,
    passport: {
        session: {},
    },
}
module.exports.version = '0.0.1'
