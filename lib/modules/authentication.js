/// Begin with the module name
const moduleName = 'authentication'

/// Name the module init method which is used in logging
function InitAuthentication(initial, authenticationOps = {}) {
    /// dependencies are scoped to the module itself
    const refresh = require('passport-oauth2-refresh')
    const crypto = require('crypto')
    const passport = require('passport')
    const util = require('../util')(this.config.appRoot)

    const { BasicStrategy } = require('passport-http')
    const { Strategy: CookieStrategy } = require('passport-cookie')
    const { Strategy: LocalStrategy } = require('passport-local')
    const { Strategy: ImgurStrategy } = require('passport-imgur')
    const { Strategy: RedditStrategy } = require('passport-reddit')
    const { Strategy: GoogleStrategy } = require('passport-google-oauth2')
    const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt')

    /*
		Note: This is where we set up application-wide api authentication. We are
		checking the defaults for these api values when we should be checking a "keys"
		or "api" option, that overrides whenever a subdomain configurationdoes not have
		these values set.
	*/

    this.config.authentication = this.getCoreOpts(moduleName, authenticationOps, initial)
    this.authTokens.default = this.config.authentication

    const authsInitialized = []

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
                    const localOpts = util.merge(
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

                        this.log.debug('[Local Auth] attempt', {
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

                    passport.use(new LocalStrategy(localOpts, scheme.validateUser))
                    authsInitialized.push({ internal: 'local', credentials: scheme.credentials })
                    break

                case 'cookie':
                    const cookieOpts = util.merge(
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
                        this.log.debug('[Cookie Auth] attempt', { jwt_payload: p, scheme })

                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }
                        return d(null, false)
                    }
                    /// Always use the cookie validator here, cookies are set globally to the app
                    scheme.validateUser = !!scheme.validateUser
                        ? scheme.validateUser
                        : cookieValidator

                    passport.use(new CookieStrategy(cookieOpts, cookieValidator))
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

                        this.log.debug('[Basic Auth] attempt', {
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

                    passport.use(new BasicStrategy(scheme.validateUser))
                    authsInitialized.push({ internal: 'basic', credentials: scheme.credentials })
                    break

                case 'jwt':
                    const jwtOpts = util.merge(
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
                        this.log.debug('[JWT Auth] attempt', { jwt_payload: p, scheme })

                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }

                        return d(null, false)
                    }
                    const jwtOrError = scheme.credentials ? jwtValidator : noValidator
                    scheme.validateUser = !!scheme.validateUser ? scheme.validateUser : jwtOrError

                    passport.use(new JwtStrategy(jwtOpts, scheme.validateUser))
                    authsInitialized.push({ internal: 'jwt', secret: jwtOpts.secretOrKey })
                    break

                default:
                    logMessage = 'scheme not supported for API'
                    break
            }

            this.log.debug(logMessage, scheme)
        })
    }

    const configurePassportMiddleware = (
        securityOpts = {},
        middlewareName,
        authStrategyMethod,
        profileMatcher = () => false,
        keys,
    ) => {
        if (!authStrategyMethod) return

        const setTokensForSubdomain = (subdomain, accessToken, refreshToken, profile) => {
            if (profileMatcher(profile, subdomain)) {
                const currentTokens = this.authTokens[subdomain][middlewareName]

                this.authTokens[subdomain][middlewareName][keys.accessToken] = accessToken
                this.authTokens[subdomain][middlewareName][keys.refreshToken] =
					currentTokens[keys.refreshToken] || refreshToken
                this.authTokens[subdomain][middlewareName][keys.profile] =
                    currentTokens[keys.profile] || profile

                this.log.status(
                    `setting ${middlewareName} authentication information for subdomain: ${subdomain}`,
                    this.authTokens[subdomain][middlewareName],
                )

                return true
            }

            return false
        }

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

        const attemptToAuthorizeForSubdomain = (req, accessToken, refreshToken, profile, done) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            const profilesMatched = setTokens(
                accessToken,
                refreshToken,
                profile,
                subdomain !== 'index' ? subdomain : null,
            )

            if (profilesMatched.length) {
                this.log.status(`user authenticated via third party auth [${middlewareName}]`, {
                    profile,
                })

                // return process.nextTick(() => {
                return done(null, profile)
                // })
            }

            /// Someone else wants to authorize our app? Why?
            this.app.log.error('Someone else wants to authorize our app? Why?', {
                auth: middlewareName,
                profile,
            })

            /// Do not authenticate this user
            // return process.nextTick(() => {
            return done(null, false)
            // })
        }

        const subdomainGetTokenRequest = (subdomain, req, res) => {
            if (this.isValidRequestOrigin(req)) {
                const response = {}
                const subdomainAuth = this.authTokens[subdomain][middlewareName]

                // response[keys.profile] = subdomainAuth[keys.profile]
                // response[keys.clientAuthorization] = subdomainAuth[keys.clientAuthorization]

                // response[keys.refreshToken] = subdomainAuth[keys.refreshToken]
                response[keys.accessToken] = subdomainAuth[keys.accessToken]
                // response[keys.profile] = subdomainAuth[keys.profile]

                this.log.debug(`${middlewareName} getToken response`, {
                    subdomain,
                    subdomainAuth,
                    apiResponse: response,
                })

                // This will only return the access token if the request is coming from the site itself
                return res.json(response)
            }

            return res.status(401).end()
        }

        keys = keys || {
            clientID: `${middlewareName}ClientID`,
            clientSecret: `${middlewareName}ClientSecret`,
            callbackURL: `${middlewareName}CallbackURL`,
            accessToken: `${middlewareName}AccessToken`,
            refreshToken: `${middlewareName}RefreshToken`,
        }

        const convertAuthOptsToStrategyOpts = (
            authOpts,
            defaults = {
                scope: ['email'],
            },
        ) => {
            const strategyOpts = util.merge(
                {
                    passReqToCallback: true,
                    scope: authOpts.scope,
                    clientID: authOpts[keys.clientID],
                    clientSecret: authOpts[keys.clientSecret],
                    callbackURL: authOpts[keys.callbackURL] || `/auth/${middlewareName}/callback`,
                    accessToken: authOpts[keys.accessToken],
                    refreshToken: authOpts[keys.refreshToken],
                },
                defaults,
            )

            return strategyOpts
        }

        const defaultStrategyOpts = convertAuthOptsToStrategyOpts(
            securityOpts[middlewareName],
            securityOpts,
        )
        const uniqueClientStrategies = []
        uniqueClientStrategies[defaultStrategyOpts.clientID] = 'default'

        /// Set the default opts
        this.authTokens.default[middlewareName] = this.authTokens.default[middlewareName]
            ? this.authTokens.default[middlewareName]
            : defaultStrategyOpts

        /// Set the per subdomain opts
        for (const subdomain of Object.keys(this.config.subdomains)) {
            const subdomainMiddlewareOpts = this.config.subdomains[subdomain][middlewareName] || {}
            this.authTokens[subdomain][middlewareName] = {}

            /// TODO: set per subdomain strategyOps overrides
            const subdomainStrategyOpts = convertAuthOptsToStrategyOpts(
                subdomainMiddlewareOpts,
                defaultStrategyOpts,
            )
            const subdomainClientID = subdomainStrategyOpts.clientID

            /// If this is a client ID we've not set before, then we need to set up a unique strategy for it
            if (Object.keys(uniqueClientStrategies).indexOf(subdomainClientID) === -1) {
                this.log.debug(`New ClientID for auth strategy discovered`, {
                    auth: middlewareName,
                    subdomainClientID,
                })
                uniqueClientStrategies[subdomainClientID] = [subdomain]
            } else if (uniqueClientStrategies[subdomainClientID] !== 'default') {
                uniqueClientStrategies[subdomainClientID].push(subdomain)
            }

            this.authTokens[subdomain][middlewareName].opts = subdomainStrategyOpts
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
                ? this.authTokens[firstSubdomainSet][middlewareName]
                : this.authTokens[firstSubdomainSet][middlewareName].opts
            const authStrategyOpts = convertAuthOptsToStrategyOpts(
                uniqueClientStrategyOpts,
                defaultStrategyOpts,
            )

            /// TODO: register a separate authStrategy per unique client id
            const authStrategy = new authStrategyMethod(
                authStrategyOpts,
                attemptToAuthorizeForSubdomain,
            )

            passport.use(authStrategy)
            refresh.use(authStrategy)

            const interceptSubdomains =
                validSubdomains.indexOf('default') !== -1 ? [] : interceptSubdomains

            /// Only allow getToken requests on non-core subdomain requests
            this.route(
                `/auth/${middlewareName}/getToken`,
                subdomainGetTokenRequest,
                ['get', 'post'],
                undefined,
                interceptSubdomains,
            )

            /// These are the only custom things for a given strategy
            this.app.get(
                `/auth/${middlewareName}`,
                this.requestHandler((subdomain, req, res, host, next) => {
                    return next()
                }, interceptSubdomains),
                passport.authenticate(middlewareName, authStrategyOpts.scope),
                // 'get',
                // interceptSubdomains,
            )

            /// TODO: allow for a custom callback method here, per strategy per subdomain
            this.app.get(
                authStrategyOpts.callbackURL,
                passport.authenticate(middlewareName, {
                    successRedirect: securityOpts.successRedirect
                        ? securityOpts.successRedirect
                        : `/profile?success=${middlewareName}`,
                    failureRedirect: securityOpts.successRedirect
                        ? securityOpts.successRedirect
                        : `/login?error=${middlewareName}`,
                }),
                // 'get',
                // false,
                // interceptSubdomains,
            )

            this.log.debug(`auth strategy [${middlewareName}] created for client ID:`, {
                clientID: authStrategyOpts.clientID,
                scope: authStrategyOpts.scope,
            })

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
                refresh.requestNewAccessToken(
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
                if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
                    refreshToken(subdomain)
                }
            }
        }
        util.setInterval(refreshTokens, refreshFrequency)
    }

    /// TODO: turn this into a imgurAPIModule
    /// TODO: switch on config.authentication.imgur instead of defaults
    if (this.config.authentication.imgur && this.config.authentication.imgur.imgurClientID) {
        configurePassportMiddleware(
            this.config.authentication,
            'imgur',
            ImgurStrategy,
            (profile, subdomain) => {
                console.log({ imgurProfile: profile, authTokens: this.authTokens })

                return (
                    profile !== null &&
                    profile.username === this.authTokens[subdomain].imgur.imgurEmailAddress
                )
            },
        )
    } else {
        this.app.get('/auth/imgur/*', (req, res) => {
            return res.send("I don't have any imgur apis set in my configuration")
        })
    }

    /// TODO: turn this into a redditAPIModule that looks for config.authentication[moduleName] for opts and sets up the authorizor
    /// TODO: send this method to the redditAPIModule middleware
    if (this.config.authentication.reddit && this.config.authentication.reddit.redditClientID) {
        configurePassportMiddleware(
            this.config.authentication,
            'reddit',
            RedditStrategy,
            (profile, subdomain) => {
                console.log({ redditProfile: profile, authTokens: this.authTokens })
                return (
                    profile !== null &&
                    profile.username === this.authTokens[subdomain].reddit.redditEmailAddress
                )
            },
        )

        // const redditOpts = {
        //     clientID: this.config.authentication.reddit.redditClientID,
        //     clientSecret: this.config.authentication.reddit.redditClientSecret,
        //     callbackURL: this.config.authentication.reddit.redditCallbackURL || '/auth/reddit/callback',
        //     passReqToCallback: true,
        // }

        // this.log.info('configuring reddit API authentication for appID:', redditOpts.clientID)

        // this.authTokens.default.reddit = {}

        // const setRedditTokens = (accessToken, refreshToken, profile) => {
        //     const profilesMatched = []

        //     for (const subdomain of Object.keys(this.config.subdomains)) {
        //         if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
        //             if (
        //                 profile !== null &&
        //                 profile.username === this.authTokens[subdomain].reddit.imgurEmailAddress
        //             ) {
        //                 this.log(
        //                     'setting reddit authentication information for subdomain:',
        //                     subdomain,
        //                 )
        //                 this.authTokens[subdomain].reddit.redditAccessToken =
        //                     accessToken || this.authTokens[subdomain].reddit.redditAccessToken
        //                 this.authTokens[subdomain].reddit.redditRefreshToken =
        //                     refreshToken || this.authTokens[subdomain].reddit.redditRefreshToken
        //                 this.authTokens[subdomain].reddit.redditProfile =
        //                     this.authTokens[subdomain].reddit.redditProfile || profile
        //                 this.authTokens[subdomain].reddit.redditUserName =
        //                     this.authTokens[subdomain].reddit.redditUserName || profile.name

        //                 profilesMatched.push(profile)
        //             }
        //         }
        //     }

        //     return profilesMatched
        // }

        // const redditStrategy = new RedditStrategy(
        //     redditOpts,
        //     (req, accessToken, refreshToken, profile, done) => {
        //         const redditProfilesMatched = setRedditTokens(accessToken, refreshToken, profile)
        //         if (redditProfilesMatched.length) {
        //             this.log.debug('reddit auth callback with valid profile', profile)
        //             return done(null, profile)
        //         }

        //         // Someone else wants to authorize our app? Why?
        //         this.log.error('Someone else wants to authorize our app? Why?', {
        //             redditProfile: profile,
        //         })

        //         /// Do not authenticate this user
        //         return done(null, false)
        //         // process.nextTick(() => done())
        //     },
        // )

        // const redditRefreshFrequency = 29 * (1000 * 60 * 60 * 24) // 29 days
        // const refreshRedditTokens = () => {
        //     const theRefreshTokenToUse = this.authTokens.default.reddit.redditRefreshToken
        //     this.log.status(
        //         'attempting to refresh reddit access token using the refresh token:',
        //         theRefreshTokenToUse,
        //     )
        //     refresh.requestNewAccessToken(
        //         'reddit',
        //         theRefreshTokenToUse,
        //         (err, accessToken, refreshToken) => {
        //             this.log('reddit access token has been refreshed:', refreshToken)
        //             setRedditTokens(accessToken, refreshToken, null)
        //         },
        //     )
        // }
        // util.setInterval(refreshRedditTokens, redditRefreshFrequency)

        // passport.use(redditStrategy)
        // refresh.use(redditStrategy)

        // // Reddit OAuth2 Integration
        // this.app.get('/auth/reddit', (req, res, next) => {
        //     req.session.state = crypto.randomBytes(32).toString('hex')
        //     this.log('authenticating reddit')

        //     return passport.authenticate('reddit', {
        //         state: req.session.state,
        //         duration: 'permanent',
        //     })(req, res, next)
        // })
        // this.app.get('/auth/reddit/callback', (req, res, next) => {
        //     if (req.query.state == req.session.state) {
        //         return passport.authenticate('reddit', {
        //             successRedirect: '/',
        //             failureRedirect: '/fail',
        //         })(req, res, next)
        //     } else {
        //         return next(new Error(403))
        //     }
        // })
        // this.app.post('/auth/reddit/getToken', (req, res) => {
        //     const subdomain = util.getSubdomainPrefix(this.config, req)
        //     let tokensValue = 'unauthorized access'

        //     if (this.isValidRequestOrigin(req)) {
        //         tokensValue = {
        //             redditRefreshToken: this.authTokens[subdomain].reddit.redditRefreshToken,
        //             redditAccessToken: this.authTokens[subdomain].reddit.redditAccessToken,
        //             redditProfile: this.authTokens[subdomain].reddit.redditProfile,
        //         }
        //     }

        //     // This will only return the reddit access token if the request is coming from the site itself
        //     return res.json({
        //         redditTokens: tokensValue,
        //     })
        // })
    } else {
        this.app.get('/auth/reddit/*', (req, res) => {
            const responseMessage = "I don't have any reddit apis set in my configuration"
            res.send(responseMessage)
        })
    }

    /// TODO: turn this into a googleAPIModule
    /// TODO: switch on config.authentication.google instead of defaults
    if (this.config.authentication.google && this.config.authentication.google.googleClientID) {
        configurePassportMiddleware(
            Object.assign(this.config.authentication, { scope: ['email', 'profile'] }),
            'google',
            GoogleStrategy,
            (profile, subdomain) => {
                console.log({ googleProfile: profile, authTokens: this.authTokens })
                return (
                    profile !== null &&
                    profile.username === this.authTokens[subdomain].google.googleEmailAddress
                )
            },
        )
    } else {
        this.app.get('/auth/google/*', (req, res) => {
            const responseMessage = "I don't have any google apis set in my configuration"
            res.status(404).send(responseMessage)
        })
    }

    if (authsInitialized.length) {
        this.log.info(
            `🗝  authorization providers have been initialized ${util.consoleLogEmojiNumber(
                authsInitialized.length,
            )}`,
            this.config.debug ? authsInitialized : undefined,
        )
    }
}

module.exports = InitAuthentication
module.exports.module = moduleName
module.exports.description = 'Handles OATH requests for authenticating with third-party APIs'
module.exports.defaults = false
module.exports.version = '0.0.1'
