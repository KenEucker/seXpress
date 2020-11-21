const refresh = require('passport-oauth2-refresh')
const crypto = require('crypto')
const passport = require('passport')
const util = require('../util')()

const { BasicStrategy } = require('passport-http')
const { Strategy: CookieStrategy } = require('passport-cookie')
const { Strategy: LocalStrategy } = require('passport-local')
const { Strategy: ImgurStrategy } = require('passport-imgur')
const { Strategy: RedditStrategy } = require('passport-reddit')
const { Strategy: GoogleStrategy } = require('passport-google-oauth2')
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt')

const moduleName = 'authentication'
module.exports = function (authenticationOps = {}) {
    /*
		Note: This is where we set up application-wide api authentication. We are
		checking the defaults for these api values when we should be checking a "keys"
		or "api" option, that overrides whenever a subdomain configurationdoes not have
		these values set.There should also be a more intelligent way of setting "defaults"?
	*/
	this.config.authentication = this.getCoreOpts(moduleName, authenticationOps, {})
	this.authTokens.default = this.config.authentication
	
	/// TODO: get list of domains to authenticate from the config and use only those

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
            let logMessage = `🔑  setting [${scheme.name}] auth strategy`

            switch (scheme.name) {
                case 'local':
                    const localOpts = util.merge(
                        {
                            usernameField: scheme.usernameField || 'username',
                            passwordField: scheme.passwordField || 'password',
                        },
                        scheme,
                    )

                    scheme.credentials = scheme.credentials || this.config.authentication.credentials
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
                    break

                case 'cookie':
                    const cookieOpts = util.merge(
                        {
                            cookieName: this.config.appName,
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
                    break

                case 'basic':
                    scheme.credentials = scheme.credentials || this.config.authentication.credentials

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
                    break

                case 'jwt':
                    const jwtOpts = util.merge(
                        {
                            jwtFromRequest: ExtractJwt.fromAuthHeaderWithScheme('JWT'),
                            secretOrKey: scheme.credentials
                                ? scheme.credentials.secret
                                : this.config.authentication.secret || this.config.appName,
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
                    break

                default:
                    logMessage = 'scheme not supported for API'
                    break
            }

            this.log.debug(logMessage, scheme)
        })
	}

	const configurePassportMiddleware = (securityOpts = {}, middlewareName, authStrategyMethod, profileMatcher = () => false, keys) => {
		if (!authStrategyMethod) return

		keys = keys || {
			clientID: `${middlewareName}ClientID`,
			clientSecret: `${middlewareName}ClientSecret`,
			clientCallbackURL: `${middlewareName}ClientCallbackURL`,
			clientAccessToken: `${middlewareName}ClientAccessToken`,
			clientRefreshToken: `${middlewareName}ClientRefreshToken`,
		}

		const strategyOpts = {
			passReqToCallback: true,
			scope: securityOpts.scope || ['email'],
			clientID: securityOpts[middlewareName][keys.clientID],
			clientSecret: securityOpts[middlewareName][keys.clientSecret],
			callbackURL: securityOpts[middlewareName][keys.clientCallbackURL] || `/auth/${middlewareName}/callback`,
			clientAccessToken: securityOpts[middlewareName][keys.clientAccessToken],
			clientRefreshToken: securityOpts[middlewareName][keys.clientRefreshToken],
		}

        this.log.info(
            `configuring ${middlewareName} API authentication for appID:`,
            securityOpts[middlewareName][keys.clientID],
        )

		this.authTokens.default[middlewareName] = this.authTokens.default[middlewareName] ? this.authTokens.default[middlewareName] : strategyOpts
		
		for (const subdomain of Object.keys(this.config.subdomains)) {
			this.authTokens[subdomain][middlewareName] = securityOpts[middlewareName]
		}

        const setTokens = (accessToken, refreshToken, profile) => {
            const profilesMatched = []

            for (const subdomain of Object.keys(this.config.subdomains)) {
                if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
                    if (profileMatcher(profile, subdomain)) {
                        this.authTokens[subdomain][middlewareName][keys.clientAccessToken] = accessToken
                        this.authTokens[subdomain][middlewareName][keys.clientRefreshToken] =
                            this.authTokens[subdomain][middlewareName][keys.clientRefreshToken] || refreshToken
                        this.authTokens[subdomain][middlewareName][keys.clientProfile] =
                            this.authTokens[subdomain][middlewareName][keys.clientProfile] || profile

                        profilesMatched.push(profile)

                        this.log(
                            `${middlewareName} authentication information for subdomain: ${subdomain}`,
                            this.authTokens[subdomain][middlewareName],
                        )
                    }
                }
            }

            return profilesMatched
        }

        const authStrategy = new authStrategyMethod(
            strategyOpts,
            (request, accessToken, refreshToken, profile, done) => {
                const profilesMatched = setTokens(accessToken, refreshToken, profile)
                if (profilesMatched) {
                    return done(null, profile)
                }

                /// Someone else wants to authorize our app? Why?
                this.app.log.error('Someone else wants to authorize our app? Why?', {
					auth: middlewareName,
                    profile,
                })

                /// Do not authenticate this user
                return done(null, false)
            },
        )
        passport.use(authStrategy)
        refresh.use(authStrategy)

        const refreshFrequency = securityOpts.refreshFrequency || 29 * (1000 * 60 * 60 * 24) // 29 days
        const refreshTokens = () => {
            const theRefreshTokenToUse = this.authTokens.default[middlewareName][keys.clientRefreshToken]
            this.log.status(
                `attempting to refresh ${middlewareName} access token using the refresh token:`,
                theRefreshTokenToUse,
            )
            refresh.requestNewAccessToken(
                middlewareName,
                theRefreshTokenToUse,
                (err, accessToken, refreshToken) => {
                    this.log.status(`${middlewareName} access token has been refreshed:`, refreshToken)
                    setTokens(accessToken, refreshToken, null)
                },
            )
        }
		util.setInterval(refreshTokens, refreshFrequency)
        this.route(`/auth/${middlewareName}/getToken`, (req, res) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            const response = {}
			response[keys.clientProfile] = this.authTokens[subdomain][middlewareName][keys.clientProfile]
			response[keys.clientAuthorization] = this.authTokens[subdomain][middlewareName][keys.clientAuthorization]
			
            this.log.debug(`${middlewareName} getToken response`, {
                apiResponse: response,
            })

            if (this.isValidRequestOrigin(req)) {
                response[keys.clientRefreshToken] = this.authTokens[subdomain][middlewareName][keys.clientRefreshToken]
                response[keys.clientAccessToken] = this.authTokens[subdomain][middlewareName][keys.clientAccessToken]
                response[keys.clientProfile] = this.authTokens[subdomain][middlewareName][keys.clientProfile]
            }

            // This will only return the access token if the request is coming from the site itself
            return res.json(response)
        }, 'get', true)

        /// These are the only custom things for a given strategy
        this.app.get(
            `/auth/${middlewareName}`,
            passport.authenticate(middlewareName, securityOpts.scope),
		)
		console.log({strategyOpts})
        this.app.get(
            strategyOpts.callbackURL,
            passport.authenticate(middlewareName, {
                successRedirect:  securityOpts.successRedirect ? securityOpts.successRedirect : `/profile?success=${middlewareName}`,
                failureRedirect:  securityOpts.successRedirect ? securityOpts.successRedirect : `/login?error=${middlewareName}`,
            }),
        )
	}

    /// TODO: turn this into a imgurAPIModule
    /// TODO: switch on config.authentication.imgur instead of defaults
    if (this.config.authentication.imgur && this.config.authentication.imgur.imgurClientID) {
		configurePassportMiddleware({ ...this.config.authentication }, 'imgur', ImgurStrategy, (profile, subdomain) => {
			console.log({ imgurProfile: profile, authTokens: this.authTokens})

			return profile !== null && profile.username === this.authTokens[subdomain].imgur.imgurEmailAddress
		})

        // const imgurOpts = {
        //     clientID: this.config.authentication.imgur.imgurClientID,
        //     clientSecret: this.config.authentication.imgur.imgurClientSecret,
        //     callbackURL: this.config.authentication.imgur.imgurCallbackURL || '/auth/imgur/callback',
        //     passReqToCallback: true,
        // }
        // this.log.info('configuring imgur API authentication for appID:', imgurOpts.clientID)
        // this.authTokens.default.imgur = {}

        // const setImgurTokens = (accessToken, refreshToken, profile) => {
        //     const profilesMatched = []

        //     for (const subdomain of Object.keys(this.config.subdomains)) {
        //         if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
        //             if (
        //                 profile !== null &&
        //                 profile.username === this.authTokens[subdomain].imgur.imgurEmailAddress
        //             ) {
        //                 this.authTokens[subdomain].imgur.imgurAccessToken =
        //                     accessToken || this.authTokens[subdomain].imgur.imgurAccessToken
        //                 this.authTokens[subdomain].imgur.imgurRefreshToken =
        //                     refreshToken || this.authTokens[subdomain].imgur.imgurRefreshToken
        //                 this.authTokens[subdomain].imgur.imgurProfile =
        //                     this.authTokens[subdomain].imgur.imgurProfile || profile

        //                 profilesMatched.push(profile)

        //                 this.log.status(
        //                     `imgur authentication information for subdomain: ${subdomain}`,
        //                     this.authTokens[subdomain].imgur,
        //                 )
        //             }
        //         }
        //     }

        //     return profilesMatched
        // }

        // const imgurStrategy = new ImgurStrategy(
        //     imgurOpts,
        //     (req, accessToken, refreshToken, profile, done) => {
        //         const imgurProfilesSet = setImgurTokens(accessToken, refreshToken, profile)
        //         if (imgurProfilesSet.length) {
        //             this.log.status('imgur auth callback with valid profile', {
        //                 profiles: imgurProfilesSet,
        //             })
        //             return done(null, profile)
        //         }

        //         /// Someone else wants to authorize our app? Why?
        //         this.app.log.error('Someone else wants to authorize our app? Why?', {
        //             imgurProfile: profile,
        //         })

        //         /// Do not authenticate this user
        //         return done(null, false)
        //     },
        // )
        // passport.use(imgurStrategy)
        // refresh.use(imgurStrategy)

        // const imgurRefreshFrequency = 29 * (1000 * 60 * 60 * 24) // 29 days
        // const refreshImgurTokens = () => {
        //     const theRefreshTokenToUse = this.authTokens.default.imgur.imgurRefreshToken
        //     this.log.status(
        //         'attempting to refresh imgur access token using the refresh token:',
        //         theRefreshTokenToUse,
        //     )
        //     refresh.requestNewAccessToken(
        //         'imgur',
        //         theRefreshTokenToUse,
        //         (err, accessToken, refreshToken) => {
        //             this.log('imgur access token has been refreshed:', refreshToken)
        //             setImgurTokens(accessToken, refreshToken, null)
        //         },
        //     )
        // }
        // util.setInterval(refreshImgurTokens, imgurRefreshFrequency)

        // // Imgur OAuth2 Integration
        // this.app.get('/auth/imgur', passport.authenticate('imgur'))
        // this.app.get(
        //     '/auth/imgur/callback',
        //     passport.authenticate('imgur', {
        //         session: false,
        //         failureRedirect: '/fail',
        //         successRedirect: '/',
        //     }),
        // )
        // this.app.post('/auth/imgur/getToken', (req, res) => {
        //     const subdomain = util.getSubdomainPrefix(this.config, req)
        //     const response = {
        //         imgurAlbumHash: this.config.subdomains[subdomain].imgur.imgurAlbumHash,
        //         imgurAuthorization: this.config.subdomains[subdomain].imgur.imgurAuthorization,
        //     }
        //     this.log.debug({
        //         imgurApiResponse: response,
        //     })

        //     if (this.isValidRequestOrigin(req)) {
        //         response.imgurRefreshToken = this.authTokens[subdomain].imgur.imgurRefreshToken
        //         response.imgurAccessToken = this.authTokens[subdomain].imgur.imgurAccessToken
        //         response.imgurProfile = this.authTokens[subdomain].imgur.imgurProfile
        //     }

        //     // This will only return the imgur access token if the request is coming from the site itself
        //     return res.json(response)
        // })
    } else {
        this.app.get('/auth/imgur/*', (req, res) => {
            return res.send("I don't have any imgur apis set in my configuration")
        })
    }

    /// TODO: turn this into a redditAPIModule
    /// TODO: switch on config.authentication.reddit instead of defaults
    if (this.config.authentication.reddit && this.config.authentication.reddit.redditClientID) {
		configurePassportMiddleware({ ...this.config.authentication }, 'reddit', RedditStrategy, (profile, subdomain) => {
			console.log({ redditProfile: profile, authTokens: this.authTokens})
			return profile !== null && profile.username === this.authTokens[subdomain].reddit.redditEmailAddress
		})

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
		configurePassportMiddleware({ ...this.config.authentication, scope: ['email', 'profile'] }, 'google', GoogleStrategy, (profile, subdomain) => {
			console.log({ googleProfile: profile, authTokens: this.authTokens})
			return profile !== null && profile.username === this.authTokens[subdomain].google.googleEmailAddress
		})
    } else {
        this.app.get('/auth/google/*', (req, res) => {
            const responseMessage = "I don't have any google apis set in my configuration"
            res.status(404).send(responseMessage)
        })
	}
	
	this.log.info(`🗝 	request authentication and third party auth providers configured`)
}
module.exports.module = moduleName
module.exports.description = 'Handles OATH requests for authenticating with third-party APIs'
