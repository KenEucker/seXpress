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
    this.getCoreOpts(moduleName, authenticationOps)

    /// If security is enabled, set up basic authentication
    if (this.config.security.enabled) {
        const allSchemes = ['local', 'basic', 'jwt', 'cookie']
        const schemes = this.config.security.schemes || allSchemes
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
            let logMessage = `setting [${scheme.name}] auth strategy`

            switch (scheme.name) {
                case 'local':
                    const localOpts = util.merge(
                        {
                            usernameField: scheme.usernameField || 'username',
                            passwordField: scheme.passwordField || 'password',
                        },
                        scheme,
                    )

                    scheme.credentials = scheme.credentials || this.config.security.credentials
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
                        d(null, false)
                    }
                    /// Always use the cookie validator here, cookies are set globally to the app
                    scheme.validateUser = !!scheme.validateUser
                        ? scheme.validateUser
                        : cookieValidator

                    passport.use(new CookieStrategy(cookieOpts, cookieValidator))
                    break

                case 'basic':
                    scheme.credentials = scheme.credentials || this.config.security.credentials

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

                        d(null, false)
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
                                : this.config.security.secret || this.config.appName,
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

                        d(null, false)
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

    /// TODO: turn this into a imgurAPIModule
    /// TODO: switch on config.security.imgur instead of defaults
    if (this.config.defaults.imgur && this.config.defaults.imgur.imgurClientID) {
        const imgurOpts = {
            clientID: this.config.defaults.imgur.imgurClientID,
            clientSecret: this.config.defaults.imgur.imgurClientSecret,
            callbackURL: this.config.defaults.imgur.imgurCallbackURL || '/auth/imgur/callback',
            passReqToCallback: true,
        }
        this.log.info('configuring imgur API authentication for appID:', imgurOpts.clientID)
        this.authTokens.default.imgur = {}

        const setImgurTokens = (accessToken, refreshToken, profile) => {
            const profilesMatched = []

            for (const subdomain of Object.keys(this.config.subdomains)) {
                if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
                    if (
                        profile !== null &&
                        profile.username === this.authTokens[subdomain].imgur.imgurEmailAddress
                    ) {
                        this.authTokens[subdomain].imgur.imgurAccessToken =
                            accessToken || this.authTokens[subdomain].imgur.imgurAccessToken
                        this.authTokens[subdomain].imgur.imgurRefreshToken =
                            refreshToken || this.authTokens[subdomain].imgur.imgurRefreshToken
                        this.authTokens[subdomain].imgur.imgurProfile =
                            this.authTokens[subdomain].imgur.imgurProfile || profile

                        profilesMatched.push(profile)

                        this.log.status(
                            `imgur authentication information for subdomain: ${subdomain}`,
                            this.authTokens[subdomain].imgur,
                        )
                    }
                }
            }

            return profilesMatched
        }

        const imgurStrategy = new ImgurStrategy(
            imgurOpts,
            (req, accessToken, refreshToken, profile, done) => {
                const imgurProfilesSet = setImgurTokens(accessToken, refreshToken, profile)
                if (imgurProfilesSet.length) {
                    this.log.status('imgur auth callback with valid profile', {
                        profiles: imgurProfilesSet,
                    })
                    return done(null, profile)
                }

                /// Someone else wants to authorize our app? Why?
                this.app.log.error('Someone else wants to authorize our app? Why?', {
                    imgurProfile: profile,
                })

                /// Do not authenticate this user
                return done(null, false)
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
    /// TODO: switch on config.security.reddit instead of defaults
    if (this.config.defaults.reddit && this.config.defaults.reddit.redditClientID) {
        const redditOpts = {
            clientID: this.config.defaults.reddit.redditClientID,
            clientSecret: this.config.defaults.reddit.redditClientSecret,
            callbackURL: this.config.defaults.reddit.redditCallbackURL || '/auth/reddit/callback',
            passReqToCallback: true,
        }

        this.log.info('configuring reddit API authentication for appID:', redditOpts.clientID)

        this.authTokens.default.reddit = {}

        const setRedditTokens = (accessToken, refreshToken, profile) => {
            const profilesMatched = []

            for (const subdomain of Object.keys(this.config.subdomains)) {
                if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
                    if (
                        profile !== null &&
                        profile.username === this.authTokens[subdomain].reddit.imgurEmailAddress
                    ) {
                        this.log(
                            'setting reddit authentication information for subdomain:',
                            subdomain,
                        )
                        this.authTokens[subdomain].reddit.redditAccessToken =
                            accessToken || this.authTokens[subdomain].reddit.redditAccessToken
                        this.authTokens[subdomain].reddit.redditRefreshToken =
                            refreshToken || this.authTokens[subdomain].reddit.redditRefreshToken
                        this.authTokens[subdomain].reddit.redditProfile =
                            this.authTokens[subdomain].reddit.redditProfile || profile
                        this.authTokens[subdomain].reddit.redditUserName =
                            this.authTokens[subdomain].reddit.redditUserName || profile.name

                        profilesMatched.push(profile)
                    }
                }
            }

            return profilesMatched
        }

        const redditStrategy = new RedditStrategy(
            redditOpts,
            (req, accessToken, refreshToken, profile, done) => {
                const redditProfilesMatched = setRedditTokens(accessToken, refreshToken, profile)
                if (redditProfilesMatched.length) {
                    this.log.debug('reddit auth callback with valid profile', profile)
                    return done(null, profile)
                }

                // Someone else wants to authorize our app? Why?
                this.log.error('Someone else wants to authorize our app? Why?', {
                    redditProfile: profile,
                })

                /// Do not authenticate this user
                return done(null, false)
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
            this.log('authenticating reddit')

            return passport.authenticate('reddit', {
                state: req.session.state,
                duration: 'permanent',
            })(req, res, next)
        })
        this.app.get('/auth/reddit/callback', (req, res, next) => {
            if (req.query.state == req.session.state) {
                return passport.authenticate('reddit', {
                    successRedirect: '/',
                    failureRedirect: '/fail',
                })(req, res, next)
            } else {
                return next(new Error(403))
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
    /// TODO: switch on config.security.google instead of defaults
    if (this.config.defaults.google && this.config.defaults.google.googleClientID) {
        const googleOpts = {
            clientID: this.config.defaults.google.googleClientID,
            clientSecret: this.config.defaults.google.googleClientSecret,
            callbackURL: this.config.defaults.google.googleCallbackURL || '/auth/google/callback',
            passReqToCallback: true,
        }
        this.log.info(
            'configuring google API authentication for appID:',
            this.config.defaults.googleClientID,
        )

        this.authTokens.default.google = {}

        const setGoogleTokens = (accessToken, refreshToken, profile) => {
            const profilesMatched = []

            for (const subdomain of Object.keys(this.config.subdomains)) {
                if (this.authTokens[subdomain] && Object.keys(this.authTokens[subdomain]).length) {
                    if (
                        profile !== null &&
                        profile.username === this.authTokens[subdomain].google.googleEmailAddress
                    ) {
                        this.authTokens[subdomain].google.googleAccessToken = accessToken
                        this.authTokens[subdomain].google.googleRefreshToken =
                            this.authTokens[subdomain].google.googleRefreshToken || refreshToken
                        this.authTokens[subdomain].google.googleProfile =
                            this.authTokens[subdomain].google.googleProfile || profile

                        profilesMatched.push(profile)

                        this.log(
                            `google authentication information for subdomain: ${subdomain}`,
                            this.authTokens[subdomain].google,
                        )
                    }
                }
            }

            return profilesMatched
        }

        const googleStrategy = new GoogleStrategy(
            googleOpts,
            (request, accessToken, refreshToken, profile, done) => {
                const googleProfilesMatched = setGoogleTokens(accessToken, refreshToken, profile)
                if (googleProfilesMatched) {
                    return done(null, profile)
                }

                /// Someone else wants to authorize our app? Why?
                this.app.log.error('Someone else wants to authorize our app? Why?', {
                    googleProfile: profile,
                })

                /// Do not authenticate this user
                return done(null, false)
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
                googleProfile: this.authTokens[subdomain].google.googleProfile,
                googleAuthorization: this.authTokens[subdomain].google.googleAuthorization,
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
            googleOpts.callbackURL,
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
module.exports.module = moduleName
module.exports.description = 'Handles OATH requests for authenticating with third-party APIs'
