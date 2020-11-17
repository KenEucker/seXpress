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

module.exports = function () {
    /*
		Note: This is where we set up application-wide api authentication. We are
		checking the defaults for these api values when we should be checking a "keys"
		or "api" option, that overrides whenever a subdomain configurationdoes not have
		these values set.There should also be a more intelligent way of setting "defaults"?
	*/

    /// If security is enabled, set up basic authentication
    if (this.config.security.enabled) {
        const allSchemes = ['local', 'basic', 'bearer', 'cookie']
        const schemes = this.config.security.schemes || allSchemes
        const noValidator = function NONE(u, p, d) {
            d('no validation method set')
        }

        schemes.forEach((scheme) => {
            const allOrNothingScheme = typeof scheme === 'string'
            scheme = !allOrNothingScheme
                ? scheme
                : {
                      name: scheme,
                  }
            let logMessage = `setting [${scheme.name}] auth strategy`

            switch (scheme.name) {
                case 'local':
					const localOpts = util.merge({
							usernameField: scheme.usernameField || 'username',
							passwordField: scheme.passwordField || 'password',
						}, scheme)
					
					scheme.credentials = scheme.credentials || this.config.security.credentials
                    const localUsername = scheme.credentials ? scheme.credentials.username : null
                    const localPassword = scheme.credentials ? scheme.credentials.password : null

                    const localValidator = (u, p, d) => {
                        const usernamePassed = !!localUsername ? RegExp(localUsername).test(u) : true
                        const passwordPassed = !!localPassword ? RegExp(localPassword).test(p) : true

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
                        d(null, false)
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
                        const usernamePassed = !!localUsername ? RegExp(localUsername).test(u) : true
                        const passwordPassed = !!localPassword ? RegExp(localPassword).test(p) : true
                        this.log.debug('[Cookie Auth] attempt', { jwt_payload: p, scheme })

                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }
                        d(null, false)
					}
					/// Always use the cookie validator here, cookies are set globally to the app
                    scheme.validateUser = !!scheme.validateUser ? scheme.validateUser : cookieValidator

                    passport.use(new CookieStrategy(cookieOpts, cookieValidator))
                    break

                case 'basic':
                    scheme.credentials = scheme.credentials || this.config.security.credentials

                    const basicUsername = scheme.credentials ? scheme.credentials.username : null
                    const basicPassword = scheme.credentials ? scheme.credentials.password : null
					
                    const basicValidator = (u, p, d) => {
                        const usernamePassed = !!basicUsername ? RegExp(basicUsername).test(u) : true
                        const passwordPassed = !!basicPassword ? RegExp(basicPassword).test(p) : true

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

                        d(null, false)
                    }
                    const basicOrError = scheme.credentials ? basicValidator : noValidator
                    scheme.validateUser = !!scheme.validateUser ? scheme.validateUser : basicOrError

                    passport.use(new BasicStrategy(scheme.validateUser))
                    break

                case 'bearer':
                    const jwtOpts = util.merge(
                        {
                            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                            secretOrKey: this.config.security.secret || 'secret',
                            issuer: this.config.host,
                            audience: this.config.host,
                        },
                        scheme,
                    )

                    const bearerValidator = (p, d) => {
                        this.log.debug('[Bearer Auth] attempt', { jwt_payload: p, scheme })

                        if (usernamePassed && passwordPassed) {
                            return d(null, { username: u })
                        }

                        d(null, false)
                    }
                    const bearerOrError = scheme.credentials ? bearerValidator : noValidator
                    scheme.validateUser = !!scheme.validateUser
                        ? scheme.validateUser
                        : bearerOrError

                    passport.use(new JwtStrategy(jwtOpts, scheme.validateUser))
                    break

                default:
                    logMessage = 'scheme not supported for API'
                    break
            }

            this.log.debug(logMessage, scheme)
        })
    }

    /// TODO: turn this into a imgurAPIModule
    if (this.config.defaults.imgurClientID) {
        this.log.info(
            'configuring imgur API authentication for appID:',
            this.config.defaults.imgurClientID,
        )
        this.authTokens.default.imgur = {}

        const setImgurTokens = (accessToken, refreshToken, profile) => {
            for (const subdomain of Object.keys(this.config.subdomains)) {
				if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
					this.authTokens[subdomain].imgur.imgurAccessToken = accessToken
					this.authTokens[subdomain].imgur.imgurRefreshToken =
						this.authTokens[subdomain].imgur.imgurRefreshToken || refreshToken
					this.authTokens[subdomain].imgur.imgurProfile =
						this.authTokens[subdomain].imgur.imgurProfile || profile

					this.log(
						`imgur authentication information for subdomain: ${subdomain}`,
						this.authTokens[subdomain].imgur,
					)
				}
            }
        }

        const imgurStrategy = new ImgurStrategy(
            {
                clientID: this.config.defaults.imgurClientID,
                clientSecret: this.config.defaults.imgurClientSecret,
                callbackURL: this.config.defaults.imgurCallbackURL,
                passReqToCallback: true,
            },
            (req, accessToken, refreshToken, profile, done) => {
                // if (
                // 	profile.email ==
                // 	this.config.defaults.imgurEmailAddress
                // ) {
                this.log('imgur auth callback with valid profile', profile)
                setImgurTokens(accessToken, refreshToken, profile)
                return done(null, profile)
                // }
                /// TODO: make this error checking more accurate
                // Someone else wants to authorize our app? Why?
                // this.app.log.error(
                // 	"Someone else wants to authorize our app? Why?",
                // 	profile.email,
                // 	this.config.imgurEmailAddress
                // )

                // log('received imgur info', accessToken, refreshToken, profile)
                return done()
            },
        )
        passport.use(imgurStrategy)
        refresh.use(imgurStrategy)

        const imgurRefreshFrequency = 29 * (1000 * 60 * 60 * 24) // 29 days
        const refreshImgurTokens = () => {
            const theRefreshTokenToUse = this.authTokens.default.imgur.imgurRefreshToken
            this.log.status(
                'attempting to refresh imgur access token using the refresh token:',
                theRefreshTokenToUse,
            )
            refresh.requestNewAccessToken(
                'imgur',
                theRefreshTokenToUse,
                (err, accessToken, refreshToken) => {
                    this.log('imgur access token has been refreshed:', refreshToken)
                    setImgurTokens(accessToken, refreshToken, null)
                },
            )
        }
        util.setInterval(refreshImgurTokens, imgurRefreshFrequency)

        // Imgur OAuth2 Integration
        this.app.get('/auth/imgur', passport.authenticate('imgur'))
        this.app.get(
            '/auth/imgur/callback',
            passport.authenticate('imgur', {
                session: false,
                failureRedirect: '/fail',
                successRedirect: '/',
            }),
        )
        this.app.post('/auth/imgur/getToken', (req, res) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            const response = {
                imgurAlbumHash: this.config.subdomains[subdomain].imgur.imgurAlbumHash,
                imgurAuthorization: this.config.subdomains[subdomain].imgur.imgurAuthorization,
            }
            this.log.debug({
                imgurApiResponse: response,
            })

            if (this.isValidRequestOrigin(req)) {
                response.imgurRefreshToken = this.authTokens[subdomain].imgur.imgurRefreshToken
                response.imgurAccessToken = this.authTokens[subdomain].imgur.imgurAccessToken
                response.imgurProfile = this.authTokens[subdomain].imgur.imgurProfile
            }

            // This will only return the imgur access token if the request is coming from the site itself
            return res.json(response)
        })
    } else {
        this.app.get('/auth/imgur/*', (req, res) => {
            return res.send("I don't have any imgur apis set in my configuration")
        })
    }

    /// TODO: turn this into a redditAPIModule
    if (this.config.defaults.redditClientID) {
        this.log.info(
            'configuring reddit API authentication for appID:',
            this.config.defaults.redditClientID,
        )

        this.authTokens.default.reddit = {}

        const setRedditTokens = (accessToken, refreshToken, profile) => {
            // FOR DOMAIN SPECIFIC USER ACCOUNTS ( DO NOT DELETE )
            // var subdomain = util.getSubdomainPrefix(this.config, req)

            // authTokens["imgur"][subdomain].imgurRefreshToken = refreshToken
            // authTokens["imgur"][subdomain].imgurAccessToken = accessToken
            // authTokens["imgur"][subdomain].imgurProfile = profile

            for (const subdomain of Object.keys(this.config.subdomains)) {
				if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
					this.log('setting reddit authentication information for subdomain:', subdomain)
					this.authTokens[subdomain].reddit.redditAccessToken = accessToken
					this.authTokens[subdomain].reddit.redditRefreshToken =
						this.authTokens[subdomain].reddit.redditRefreshToken || refreshToken
					this.authTokens[subdomain].reddit.redditProfile =
						this.authTokens[subdomain].reddit.redditProfile || profile
					this.authTokens[subdomain].reddit.redditUserName =
						this.authTokens[subdomain].reddit.redditUserName || profile.name
				}
            }
        }

        const redditStrategy = new RedditStrategy(
            {
                clientID: this.config.defaults.redditClientID,
                clientSecret: this.config.defaults.redditClientSecret,
                callbackURL: this.config.defaults.redditCallbackURL,
                passReqToCallback: true,
            },
            (req, accessToken, refreshToken, profile, done) => {
                // if (
                // 	profile.name ==
                // 	this.config.defaults.redditUserName
                // ) {
                this.log.debug('reddit auth callback with valid profile', profile)
                setRedditTokens(accessToken, refreshToken, profile)

                return done(null, profile)
                // }
                /// TODO: make this error checking more accurate
                // console.error(
                // 	"Someone else wants to authorize our app? Why?",
                // 	profile.name,
                // 	this.config.defaults.redditUserName
                // )
                // Someone else wants to authorize our app? Why?

                // process.nextTick(() => done())
            },
        )

        const redditRefreshFrequency = 29 * (1000 * 60 * 60 * 24) // 29 days
        const refreshRedditTokens = () => {
            const theRefreshTokenToUse = this.authTokens.default.reddit.redditRefreshToken
            this.log.status(
                'attempting to refresh reddit access token using the refresh token:',
                theRefreshTokenToUse,
            )
            refresh.requestNewAccessToken(
                'reddit',
                theRefreshTokenToUse,
                (err, accessToken, refreshToken) => {
                    this.log('reddit access token has been refreshed:', refreshToken)
                    setRedditTokens(accessToken, refreshToken, null)
                },
            )
        }
        util.setInterval(refreshRedditTokens, redditRefreshFrequency)

        passport.use(redditStrategy)
        refresh.use(redditStrategy)

        // Reddit OAuth2 Integration
        this.app.get('/auth/reddit', (req, res, next) => {
            req.session.state = crypto.randomBytes(32).toString('hex')
            this.log('authenticating')
            passport.authenticate('reddit', {
                state: req.session.state,
                duration: 'permanent',
            })(req, res, next)
        })
        this.app.get('/auth/reddit/callback', (req, res, next) => {
            if (req.query.state == req.session.state) {
                passport.authenticate('reddit', {
                    successRedirect: '/',
                    failureRedirect: '/fail',
                })(req, res, next)
            } else {
                next(new Error(403))
            }
        })
        this.app.post('/auth/reddit/getToken', (req, res) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            let tokensValue = 'unauthorized access'

            if (this.isValidRequestOrigin(req)) {
                tokensValue = {
                    redditRefreshToken: this.authTokens[subdomain].reddit.redditRefreshToken,
                    redditAccessToken: this.authTokens[subdomain].reddit.redditAccessToken,
                    redditProfile: this.authTokens[subdomain].reddit.redditProfile,
                }
            }

            // This will only return the reddit access token if the request is coming from the site itself
            return res.json({
                redditTokens: tokensValue,
            })
        })
    } else {
        this.app.get('/auth/reddit/*', (req, res) => {
            const responseMessage = "I don't have any reddit apis set in my configuration"
            res.send(responseMessage)
        })
    }

    /// TODO: turn this into a googleAPIModule
    if (this.config.defaults.googleClientID) {
        this.log.info(
            'configuring google API authentication for appID:',
            this.config.defaults.googleClientID,
        )

        this.authTokens.default.google = {}

        const setGoogleTokens = (accessToken, refreshToken, profile) => {
            for (const subdomain of Object.keys(this.config.subdomains)) {
				if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
					this.authTokens[subdomain].google.googleAccessToken = accessToken
					this.authTokens[subdomain].google.googleRefreshToken =
						this.authTokens[subdomain].google.googleRefreshToken || refreshToken
					this.authTokens[subdomain].google.googleProfile =
						this.authTokens[subdomain].google.googleProfile || profile
					this.log(
						`google authentication information for subdomain: ${subdomain}`,
						this.authTokens[subdomain].google,
					)
				}
            }
        }

        const googleClientID = this.config.defaults.googleClientID
        const googleClientSecret = this.config.defaults.googleClientSecret
        const googleCallbackURL = this.config.defaults.googleCallbackURL || '/auth/google/callback'

        const googleStrategy = new GoogleStrategy(
            {
                clientID: googleClientID,
                clientSecret: googleClientSecret,
                callbackURL: googleCallbackURL,
                passReqToCallback: true,
            },
            (request, accessToken, refreshToken, profile, done) => {
                console.log({
                    request,
                    accessToken,
                    refreshToken,
                    profile,
                    done,
                })
                setGoogleTokens(accessToken, refreshToken, profile)
                // User.findOrCreate({ googleId: profile.id }, function (err, user) {
                //   return done(err, user);
                // });
            },
        )
        passport.use(googleStrategy)
        refresh.use(googleStrategy)

        const googleRefreshFrequency = 29 * (1000 * 60 * 60 * 24) // 29 days
        const refreshGoogleTokens = () => {
            const theRefreshTokenToUse = this.authTokens.default.google.googleRefreshToken
            this.log.status(
                'attempting to refresh google access token using the refresh token:',
                theRefreshTokenToUse,
            )
            refresh.requestNewAccessToken(
                'google',
                theRefreshTokenToUse,
                (err, accessToken, refreshToken) => {
                    log('google access token has been refreshed:', refreshToken)
                    setGoogleTokens(accessToken, refreshToken, null)
                },
            )
        }
        util.setInterval(refreshGoogleTokens, googleRefreshFrequency)
        this.app.post('/auth/google/getToken', (req, res) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            const response = {
                googleAlbumHash: this.config.subdomains[subdomain].google.googleAlbumHash,
                googleAuthorization: this.config.subdomains[subdomain].google.googleAuthorization,
            }
            this.log.debug({
                googleApiResponse: response,
            })

            if (this.isValidRequestOrigin(req)) {
                response.googleRefreshToken = this.authTokens[subdomain].google.googleRefreshToken
                response.googleAccessToken = this.authTokens[subdomain].google.googleAccessToken
                response.googleProfile = this.authTokens[subdomain].google.googleProfile
            }

            // This will only return the google access token if the request is coming from the site itself
            return res.json(response)
        })

        /// These are the only custom things for a given strategy
        this.app.get(
            '/auth/google',
            passport.authenticate('google', { scope: ['email', 'profile'] }),
        )
        this.app.get(
            googleCallbackURL,
            passport.authenticate('google', {
                successRedirect: '/auth/google/success',
                failureRedirect: '/auth/google/failure',
            }),
        )
    } else {
        this.app.get('/auth/google/*', (req, res) => {
            const responseMessage = "I don't have any google apis set in my configuration"
            res.send(responseMessage)
        })
    }
}
module.exports.module = 'authentication'
module.exports.description = 'Handles OATH requests for authenticating with third-party APIs'
