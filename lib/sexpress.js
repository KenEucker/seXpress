const express = require('express')
const session = require('express-session')
const path = require('path')
const fs = require('fs')
let config = require('clobfig')()

/// TODO: put these dependencies closer to their scopes
const bodyParser = require('body-parser')
const nodemailer = require('nodemailer')
const favicon = require('serve-favicon')
const passport = require('passport')
const watch = require('watch')
const http = require('http')
const https = require('https')
const reload = require('reload')
const swaggerJSDoc = require('swagger-jsdoc')
const ejs = require('ejs')
const sass = require('sass')

/// Utilities
const util = require('./util')(config.AppRoot)
const debugFilename = util.getRootPath('config.debug.js')

const { Strategy: LocalStrategy } = require('passport-local')
const { Strategy: JwtStrategy, ExtractJwt } = require('passport-jwt')

/// TODO: put these packageJson lines into clobfig
const packageJsonPath = util.getRootPath('package.json')
const { version, title: appName, description } = fs.existsSync(packageJsonPath)
    ? require(packageJsonPath)
    : {
          version: 'null',
          title: 'sexpress',
          description: 'an express application',
      }

/// Locals
const subdomains = !!config.subdomains ? Object.keys(config.subdomains) : []
let debug = !!config.debug
    ? config.debug
    : process.argv.reduce((out, arg) => (out = out || arg.indexOf('--debug=true') !== -1), false)
// Never let debug mode run in production
debug = config.debug = process.env.NODE_ENV !== 'production' ? debug : false
config = util.merge(
    config,
    debug && fs.existsSync(debugFilename)
        ? require(debugFilename)
        : debug
        ? {
              host: 'localhost',
              port: 8080,
              sslport: 8443,
          }
        : {},
)

function _getTemplateNameFromSubdomain(opts, subdomain) {
    if (!!opts.subdomains[subdomain]) {
        return opts.subdomains[subdomain].template
    }

    return null
}

async function _sendEmail(opts, to, subject, text, callback, html, from) {
    const configEmailAddressIsSet = !!opts.email.emailAccountAddress
    const configEmailHostIsSet = !!opts.email.emailAccountHost
    const configEmailServiceIsSet = !!opts.email.emailService

    // Generate test SMTP service account from ethereal.email
    // Only needed if you don't have a real mail account for testing
    const auth = configEmailAddressIsSet
        ? {
              user: opts.email.emailAccountAddress,
              pass: opts.email.emailAccountPassword,
          }
        : await nodemailer.createTestAccount()
    const host = configEmailHostIsSet ? opts.email.emailAccountHost : 'smtp.ethereal.email'
    const port = configEmailHostIsSet ? opts.email.emailAccountPort : 587
    const secure = configEmailHostIsSet ? opts.email.emailAccountIsSecure : false
    const service = configEmailServiceIsSet ? opts.email.emailService : null

    const emailOpts = {
        from: !!from ? from : auth.user, // sender address
        to, // list of receivers
        subject, // Subject line
        text, // plain text body
        html, // html body
    }

    const transporterOpts = {
        auth,
    }

    if (configEmailServiceIsSet) {
        transporterOpts.service = service
    } else {
        // create reusable transporter object using the default SMTP transport
        transporterOpts.host = host
        transporterOpts.port = port
        transporterOpts.secure = secure // true for 465, false for other ports
        transporterOpts.auth = auth
    }
    const transporter = nodemailer.createTransport(transporterOpts)

    // send mail with defined transport object
    const info = await transporter.sendMail(emailOpts)

    return callback(info)
}

const _coreSubdomains = ['api', 'admin', 'info', 'status', 'data', 'content', 'mail', 'login']

const _defaults = {
    host: 'localhost',
    run: false,
    initSeqMessage: 'Sexy Configuration!',
    publicConfigFilter: (c) => c,
    publicFields: [],
    port: 80,
    indexControllerName: 'index',
    styleEngine: 'scss',
    overrideViewEngine: 'ejs',
    security: false,

    version,
    description,
    appName,
}

class Sexpress {
    constructor(opts = {}) {
        /// powered by expressjs
        this.app = express()

		this.authTokens = { default: {} }
        this.customApiRoutes = []

		this._customRoutesAdded = []
		this._customControllerRoutePrefix = ''

        /// Construct configuration from defaults, config files, and instantiation opts
        this.setConfiguration({
            ..._defaults,
            ...config,
            ...opts,
        })

        /// Set up the logger
        this.setLogger(util.log.setDebugging(this.config.debug))

        /// Initialize the app
        this.init()

        /// Load core modules
        this.initCoreModules()

        /// Add third party middleware support
        this.initMiddlewares(this.config.middlewares)

        if (this.config.run) this.run()
    }

    /// Begin application initialization
    init() {
        this.log.debug(`initializing sexpress application {${this.config.appName}}`, this.config)

        /// TODO: can this go into the authentication module?
        /// Initialize and configure passportjs for maintaining connections to third party auth's
        this.initPassport(this.config.passport, this.config.session, this.config.security)

        /// Initialize the application to send and recieve proper JSON
        this.initJSONResponse()

        /// Discover and add the favicon
        this.initFavicon(this.config.publicFolder)
    }

    /// Load the required modules but don't run any of them
    initCoreModules() {
        if (!this.config.modules) {
            const modulesFolderFiles = fs.readdirSync(path.join(__dirname, 'modules'))
            const modulesFiles = modulesFolderFiles.filter((f) => f.indexOf('.js') !== -1)

            this.config.modules = modulesFiles.map((m) => m.replace('.js', ''))
        }

        /// get the core modules
        this.core = require(path.join(__dirname, 'modules'))(this.config.modules)

        /// Load core modules in this order
        this.loadModules(this.core, [
            'cache',
            'logging',
            'security',
            'authentication',
            'login',
            'routing',
            'rendering',
            'templating',
            'api',
            'docs',
            'robots',
            'errors',
        ])
    }

    /**** setter methods *****/
    setLogger(logger, loud = false) {
        if (loud || !this.config.silent) {
            this.log = logger
        } else {
            this.log = (m) => m
            this.log.debug = this.log.info = this.log.status = this.log.error = this.log
        }
    }

    setConfiguration(config) {
        this.config = config

        this.config.defaults = this.config.defaults || {}
        this.config.staticFolders = this.config.staticFolders || []
        this.config.appFolder = this.config.appFolder ? this.config.appFolder : util.getRootPath('')
        this.config.publicFolder = this.config.publicFolder
            ? this.config.publicFolder
            : util.getRootPath('public')
        this.config.contentFolder = this.config.contentFolder
            ? this.config.contentFolder
            : util.getRootPath(['public', 'content'])
        this.config.sslFolder = this.config.sslFolder
            ? this.config.sslFolder
            : util.getRootPath(['config', 'ssl'])
        this.config.templatesFolder = this.config.templatesFolder
            ? this.config.templatesFolder
            : util.getRootPath('templates')
        this.config.controllersFolder = this.config.controllersFolder
            ? this.config.controllersFolder
            : util.getRootPath('controllers')
        this.config.viewsFolder = this.config.viewsFolder
            ? this.config.viewsFolder
            : util.getRootPath(path.join('controllers', 'views'))
        this.config.getRootPath = util.getRootPath

        subdomains.forEach((subdomain) => {
            if (_coreSubdomains.indexOf(subdomain) !== -1) {
                this.log.info('overriding core subdomain', subdomain)
            }
            const subdomainConfiguration = this.config.subdomains[subdomain]
            const subdomainConfigurationFields = {
                meta: ['metaUrl', 'metaType', 'metaTitle', 'metaImage', 'metaDescription', 'gaUA'],
                imgur: [
                    'imgurClientID',
                    'imgurClientSecret',
                    'imgurCallbackURL',
                    'imgurEmailAddress',
                ],
                s3: ['AwsCdnUrl', 'emailAddress', 'accessKeyId', 'secretAccessKey', 'region'],
                reddit: [
                    'redditClientID',
                    'redditClientSecret',
                    'redditCallbackURL',
                    'redditUserName',
                    'redditUserAgent',
                    'redditPassword',
                ],
                google: [
                    'googleClientID',
                    'googleClientSecret',
                    'googleCallbackURL',
                    'googleEmailAddress',
                ],
                email: [
                    'emailAccountHost',
                    'emailService',
                    'emailAccountAddress',
                    'emailAccountPassword',
                    'emailAccountIsSecure',
                    'emailAccountPort',
                ],
            }

            Object.keys(subdomainConfigurationFields).forEach((field) => {
                const fields = subdomainConfigurationFields[field]
                subdomainConfiguration[field] = util.getValuesFromObjectOrDefault(
                    fields,
                    subdomainConfiguration[field],
                    this.config.defaults,
                    this.config,
                )
            })

            this.authTokens[subdomain] = subdomainConfiguration
        })

        /// Configure SSL for a local file strategy
        const ssl = this.config.ssl || {}
        if (fs.existsSync(this.config.sslFolder)) {
            const sslFiles = fs.readdirSync(this.config.sslFolder)

            sslFiles.forEach((sslFile) => {
                const sslFileSplit = sslFile.split('.')
                const sslFileName = sslFileSplit[0]
                const sslFileExtension = path.extname(sslFile)

                if (sslFileExtension === '.pem') {
                    const sslFilePath = path.join(this.config.sslFolder, sslFile)
                    switch (sslFileName) {
                        case 'cert':
                            ssl.hasCertificate = true
                            ssl.certificateFilename = sslFilePath
                            break
                        case 'key':
                            ssl.hasCertificateKey = true
                            ssl.certificateKeyFilename = sslFilePath
                            break
                        case 'ca':
                            ssl.hasCertificateAuthority = true
                            ssl.certificateAuthorityFilename = sslFilePath
                        case 'passphrase':
                            ssl.passphrase = fs.readFileSync(sslFilePath, 'utf-8')
                            break
                    }
                }
            })
        }
        this.config.ssl = ssl

        /// Set the security settings for the application
        this.config.security =
            typeof this.config.security === 'object'
                ? this.config.security
                : { enabled: this.config.security }

        const content = {}
        if (fs.existsSync(this.config.contentFolder)) {
            const contentFiles = fs.readdirSync(this.config.contentFolder)

            contentFiles.forEach((contentFile) => {
                const contentFileSplit = contentFile.split('.')
                const contentFileName = contentFileSplit[0]
                const contentFileExtension = path.extname(contentFile)

                if (contentFileExtension === '.html') {
                    const html = fs.readFileSync(
                        path.join(this.config.contentFolder, contentFile),
                        {
                            encoding: 'utf8',
                        },
                    )
                    content[contentFileName] = html
                }
            })
        }

        this.config.content = content
    }

    /**** application methods *****/
    registerController(controller, root = '') {
        const applet = express()

        root = controller.root ? controller.root : root
        const controllerName = root ? root : this.config.indexControllerName

        this.log.info(`adding controller: ${controllerName}`)

        const prefix = `/${controller.prefix ? controller.prefix : root}`
        const veiwsFolder = path.join(this.config.controllersFolder, root, 'views')
        const viewEngine = !!controller.engine ? controller.engine : this.config.overrideViewEngine
        const viewGeneratedRoutes = []

        const logControllerAction = (action) => {
            this.log.info(`[${controllerName}] -> ${action}`)
        }

        if (!root) {
            controller.useRootPath =
                typeof controller.useRootPath !== 'undefined' ? controller.useRootPath : true
        }

        if (typeof controller.init === 'function') {
            logControllerAction('init')
            controller.init(this)
        }

        let handler,
            method,
            postfix = '',
            pathMessage,
            atLeastOneGeneratedRoute

        // allow specifying the view engine
        logControllerAction(`engine [${viewEngine}]`)
        applet.set('view engine', viewEngine)

        /// generate routes based on existing view files
        if (fs.existsSync(veiwsFolder)) {
            applet.set('views', veiwsFolder)

            fs.readdirSync(veiwsFolder).forEach((filename) => {
                const viewName = filename.replace(path.extname(filename), '')

                if (!controller[viewName]) {
                    viewGeneratedRoutes[viewName] = filename

                    controller[viewName] = (s, r, res) => {
                        return res.render(filename)
                    }
                }
            })
        }

        // generate routes based
        // on the exported methods
        for (const key in controller) {
            // "reserved" exports
            if (['show', 'list', 'edit', 'update', 'create', 'index'].indexOf(key) === -1) continue
            if (!atLeastOneGeneratedRoute) {
                atLeastOneGeneratedRoute = true
                logControllerAction('generated routes')
            }

            // route exports
            switch (key) {
                case 'show':
                    method = 'get'
                    postfix = '/:' + root + '_id'
                    break

                case 'list':
                    method = 'get'
                    postfix = 's'
                    break

                case 'edit':
                    method = 'get'
                    postfix = '/:' + root + '_id/edit'
                    break

                case 'update':
                    method = 'put'
                    postfix = '/:' + root + '_id'
                    break

                case 'create':
                    method = 'post'
                    break

                case 'index':
                    method = 'get'
                    break

                default:
                    /* istanbul ignore next */
                    throw new Error('unrecognized route: ' + root + '.' + key)
            }
            const url = prefix + postfix
            const routeIsTemplateMap = (typeof controller[key]).toLocaleLowerCase() === 'string'
            const routeIsViewMap = !!viewGeneratedRoutes[key]

            /// final path information
            pathMessage = `${method.toUpperCase()} ${url} -> ${key}`

            if (routeIsViewMap) {
                pathMessage = `${pathMessage} :: <${viewGeneratedRoutes[key]}>`
            } else if (routeIsTemplateMap) {
                pathMessage = `${pathMessage} :: [${controller[key]}]`
            } else {
                pathMessage = `${pathMessage}()`
            }

            /// setup
            if (routeIsTemplateMap) {
                handler = this.requestHandler(this.templateHandler(controller[key]))
            } else {
                handler = this.requestHandler(controller[key])
            }

            /// before middleware support
            if (controller.before) {
                applet[method](url, this.requestHandler(controller.before), handler)
            } else {
                applet[method](url, handler)
            }

            this.log.info('', [pathMessage])
        }

        // middleware custom routes
        if (typeof controller.routes === 'function') {
            this._customControllerRoutePrefix = controller.useRootPath ? '' : prefix

            const thisApp = this.app
            /// use the applet for the controller routes
            this.app = applet
            controller.routes(this)
            /// reset back to the main app
            this.app = thisApp

            this.customApiRoutes[controllerName] = this._customRoutesAdded

            logControllerAction('custom routes')
            this._customRoutesAdded.forEach((customRoute) => {
                const { method, endpoint, functionName } = customRoute
                this.log.info(
                    '',
                    `[${method.toUpperCase()}] ${endpoint} -> ${
                        functionName ? functionName : '*'
                    }()`,
                )
            })

            this._customRoutesAdded = []
            this._customControllerRoutePrefix = ''
        }

        // mount the app
        this.app.use(applet)
    }

    use(handler, handler2, handler3) {
        handler =
            typeof handler === 'string' ? `${this._customControllerRoutePrefix}${handler}` : handler

        if (handler3) {
            return this.app.use(handler, handler2, handler3)
        } else if (handler2) {
            return this.app.use(handler, handler2)
        }

        return this.app.use(handler)
    }

    loadModules(modules, order) {
        order = order || Object.keys(modules)

        if (modules) {
            for (let i = 0; i < order.length; ++i) {
                const module = order[i]
                modules[module].bind(this)()
            }
        }
    }

    secureRoute(endpoint, response, methods) {
        return this.route(endpoint, response, methods, true)
    }

    route(endpoint, response, methods = 'get', secure = false) {
        endpoint = `${this._customControllerRoutePrefix}${endpoint}`
        methods = typeof methods === 'string' ? [methods] : methods
        const functionName = util.getFunctionName(response)

        methods.forEach((method) => {
            this._customRoutesAdded.push({ method, endpoint, functionName })

            if (secure) {
                this.app[method](
                    endpoint,
                    passport.authenticate('local'),
                    this.requestHandler(response),
                )
            } else {
                this.app[method](endpoint, this.requestHandler(response))
            }
        })
    }

    templateHandler(template) {
        return (subdomain, req, res, host) => {
            if (!subdomain) {
                const hostSubdomainEnd = host.indexOf('.') + 1
                const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

                this.log.error({
                    subdomain,
                    hostNotFound: host,
                    redirectToHost,
                })

                return res.redirect(redirectToHost)
            }

            const params = typeof req.params === 'object' ? req.params : {}
            const data = this.getPublicConfig(subdomain, host, params)
            return this.renderTemplate(template, data, res)
        }
    }

    requestHandler(handler, skipLogging = false) {
        const dontLog = [
            '/public*',
            '/css*',
            '/js*',
            '/font*',
            '/webfont*',
            '/img*',
            '/media*',
            '/docs*',
        ]

        return (req, res, next) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            const host = req.headers.host
            const url = req.url
            skipLogging = skipLogging ? skipLogging : new RegExp(dontLog.join('|')).test(url)

            if (!skipLogging) {
                const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress

                this.log.status(`[${req.method}] request`, {
                    handler: handler.name || '*()',
                    url,
                    subdomain,
                    ip,
                })
            }

            return handler.call({ app: this }, subdomain, req, res, host, next)
        }
    }

    /**** getter methods *****/
    /// Only returns the keyvals stored in the app
    get(name = '') {
        this.app.get(name)
    }

    /// TODO: refactor this method to not run on every request, this is a good candidate for implementing the app cache
    getPublicConfig(subdomain, host, overrides) {
        const publicConfig = {
            host,
            SUBDOMAIN: subdomain.toUpperCase(),
            thisSubdomain: subdomain,
            debug: this.config.debug,
            content: this.config.content,
            subdomains: [],
        }

        Object.keys(this.config.subdomains).forEach((subdomainName) => {
            const subdomainInformation = this.config.subdomains[subdomainName]
            const customCssPath = path.join(__dirname, 'assets/css', `${subdomain}.css`)
            const pageData = util.getValuesFromObjectOrDefault(
                this.config.publicFields,
                subdomainInformation,
                this.config,
            )

            pageData.hasCustomCss = fs.existsSync(customCssPath)

            if (subdomain === subdomainName) {
                publicConfig.page = util.getValuesFromObjectOrDefault(
                    undefined,
                    pageData,
                    overrides,
                    undefined,
                    true,
                )
            }

            publicConfig.subdomains[subdomainName] = pageData
        })

        publicConfig.content = this.config.content

        return this.config.publicConfigFilter(publicConfig, this.config, subdomain)
    }

    getTemplateNameFromSubdomain(subdomain) {
        return _getTemplateNameFromSubdomain(this.config, subdomain)
    }

    getSubdomainOpts(req) {
        const subdomain =
            (typeof req).toLocaleLowerCase() === 'string'
                ? req
                : util.getSubdomainPrefix(this.config, req, true)

        let subdomainConfig = {}

        if (!!opts.subdomains[subdomain]) {
            subdomainConfig = this.config.subdomains[subdomain]
        } else {
            const subdomainAliased = Object.values(this.config.subdomains).filter((sub) => {
                return sub.aliases.indexOf(subdomain) !== -1
            })
            subdomainConfig = subdomainAliased.length ? subdomainAliased[0] : {}
        }

        return {
            requestSubdomain: subdomain,
            ...subdomainConfig,
            requestHost: req.hostname,
        }
    }

    getSubdomainFromAlias(alias) {
        return util.getSubdomainFromAlias(this.config, alias)
    }

    getSwaggerSpec(opts, overrides) {
        const openApiDefinition = util.merge(
            {
                openapi: opts.openapi || '3.0.1',
                info: {
                    title: opts.title || opts.appName,
                    version: opts.version,
                    description: opts.description,
                },
                // host: overrides.host || opts.host,
                servers: overrides.servers
                    ? []
                    : [
                          {
                              url: `http://${overrides.host || opts.host}`,
                          },
                      ],
            },
            overrides,
        )

        if (opts.security.enabled) {
            const securitySchemes = {
                bearer: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
                basic: {
                    type: 'http',
                    scheme: 'basic',
                },
            }

            if (opts.security.schemes) {
                Object.keys(securitySchemes).forEach((strategy) => {
                    if (opts.security.schemes.indexOf(strategy) === -1)
                        delete securitySchemes[strategy]
                })
            }

            if (opts.security.enabled === 'all') {
                openApiDefinition.security = Object.keys(securitySchemes).reduce((o, s) => {
                    o[s] = []
                    return o
                }, {})
            }

            openApiDefinition.components = { securitySchemes }
        }

        const swaggerDefinition = opts.openApiDefinition
            ? opts.openApiDefinition
            : openApiDefinition

        const jsDocOpts = {
            swaggerDefinition,
            apis: util.getControllers(opts, undefined, opts.privateApis),
        }
        return swaggerJSDoc(jsDocOpts)
    }

    /**** TODO:remove these init methods and put them into related core modules or an init module? *****/
    initApiSecurity(securityOpts = {}, jwtOpts = {}) {
        const allSchemes = ['basic', 'bearer']
        const schemes = securityOpts.schemes || allSchemes

        schemes.forEach((scheme) => {
            const allOrNothingScheme = typeof scheme === 'string'
            scheme = !allOrNothingScheme
                ? scheme
                : {
                      name: scheme,
                  }

            let logMessage = `setting ${scheme.name} security strategy`
            switch (scheme.name) {
                case 'basic':
                    const defaultUserField = 'username'
                    const defaultPassField = 'password'
                    const usernameField = allOrNothingScheme
                        ? defaultUserField
                        : scheme.usernameField || defaultUserField
                    const passwordField = allOrNothingScheme
                        ? defaultPassField
                        : scheme.passwordField || defaultPassField

                    scheme.validateUser =
                        scheme.validateUser ||
                        ((u, p, d) => {
                            if (allOrNothingScheme) {
                                return d(null, { username: u })
                            }

                            d('No Validation Method set')
                        })

                    passport.use(
                        new LocalStrategy(
                            {
                                usernameField,
                                passwordField,
                            },
                            scheme.validateUser,
                        ),
                    )
                    break

                case 'bearer':
                    jwtOpts.jwtFromRequest =
                        jwtOpts.jwtFromRequest || ExtractJwt.fromAuthHeaderAsBearerToken()
                    jwtOpts.secretOrKey = jwtOpts.secretOrKey || 'secret'
                    jwtOpts.issuer = jwtOpts.issuer || this.config.host
                    jwtOpts.audience = jwtOpts.audience || this.config.host

                    passport.use(
                        new JwtStrategy(jwtOpts, function (jwt_payload, done) {
                            console.log('HEYOOO', { jwt_payload })
                            return done(null, { name: 'test' })
                            User.findOne({ id: jwt_payload.sub }, function (err, user) {
                                if (err) {
                                    return done(err, false)
                                }
                                if (user) {
                                    return done(null, user)
                                } else {
                                    return done(null, false)
                                    // or you could create a new account
                                }
                            })
                        }),
                    )
                    break
                default:
                    logMessage = null
                    break
            }

            this.log.debug(logMessage)
        })
    }

    initFavicon(faviconFolder, faviconFileName = 'favicon.ico') {
        const faviconFilePath = path.join(faviconFolder, faviconFileName)

        if (fs.existsSync(faviconFilePath)) {
            this.log.info('favicon found', faviconFilePath)
            this.app.use(favicon(faviconFilePath))
        } else {
            this.log.error('favicon not found', faviconFilePath)
        }
    }

    initPassport(passportOpts = {}, sessionOpts = {}, securityOpts = {}) {
        /// Set up request sessions
        this.app.use(
            session(
                util.merge(
                    {
                        secret: this.config.appName,
                        resave: false,
                        saveUninitialized: false,
                    },
                    sessionOpts,
                ),
            ),
        )

        /// Initialize passportjs
        this.app.use(passport.initialize(passportOpts))
        this.app.use(passport.session({}))

        /// Initialize security schemes for our API connections
        this.initApiSecurity(securityOpts)
    }

    initMiddlewares(middlewares) {}

    initJSONResponse(urlencoded = true, spaces = 2) {
        /// Support JSON-encoded bodies
        this.app.use(express.json())
        this.app.set('json spaces', spaces)

        /// Use body-parser
        this.app.use(
            bodyParser.urlencoded({
                extended: false,
            }),
        )

        /// Support URL-encoded bodies
        if (urlencoded) {
            this.app.use(
                express.urlencoded({
                    extended: true,
                }),
            )
        }
    }

    /**** validator methods *****/
    isValidRequestOrigin(req) {
        /// All requests should match this host
        const host = this.config.host

        const origin = req.get('origin') || 'none'
        const subdomain = util.getSubdomainPrefix(this.config, req, true)
        const subdomainPrefix = `${
            subdomain == this.config.indexControllerName ? '' : `${subdomain}.`
        }`
        const path = ''
        const protocol = req.protocol
        const reconstructedUrl = `${protocol}://${subdomainPrefix}${host}${path}`

        const localhostPortIsTheSameForDebugging =
            origin === reconstructedUrl || origin === `${reconstructedUrl}:${this.config.port}`
        const originIsCorrectSubdomain = origin == `${protocol}://${subdomainPrefix}${host}`
        const originIsValid = originIsCorrectSubdomain || localhostPortIsTheSameForDebugging

        if (originIsValid) {
            this.log.debug(`origin ${origin} is valid`)
        } else {
            this.log.error(`origin ${origin} is not valid`, {
                localhostPortIsTheSameForDebugging,
                originIsCorrectSubdomain,
                reconstructedUrl,
                originIsValid,
                subdomain,
                origin,
            })
        }

        return originIsValid
    }

    sexyRenderer(viewFilePath, options, callback) {
        const self = this
        const overrideViewEngineMethod = ejs.renderFile
        const viewStyleEngineMethod = sass.renderSync

        /// Ensure the correct extension is set
        viewFilePath = `${viewFilePath.replace(`.${this.config.overrideViewEngine}`, '')}.${
            this.config.overrideViewEngine
        }`

        return overrideViewEngineMethod(viewFilePath, options, (err, viewRendered) => {
            if (err) return callback(err)

            let rendered = viewRendered
            const templateSass = viewFilePath.replace(
                `.${this.config.overrideViewEngine}`,
                `.${this.config.styleEngine}`,
            )

            if (fs.existsSync(templateSass)) {
                const styleRendered = viewStyleEngineMethod({ file: templateSass })
                const css = styleRendered.css
                self.log.debug(
                    err
                        ? 'erorr rendering embedded style'
                        : 'styles rendered and embedded into view',
                    {
                        templateFilePath: viewFilePath,
                        templateSass,
                        err,
                    },
                )
                rendered = (!!css ? `<style>\n${css}\n</style>` + '\n' : '') + rendered
            }

            return callback(null, rendered)
        })
    }

    /**** private methods *****/
    /// Protects connections to the server with an ssl certificate
    __ssl(serverOpts) {
        try {
            switch (this.config.ssl.strategy) {
                case 'letsencrypt':
                    const certDir = '/etc/letsencrypt/live'
                    const certDirectoryFiles = fs.readdirSync(certDir)
                    const certficates = []

                    certDirectoryFiles.forEach((domain) => {
                        const domainPath = path.join(certDir, domain)
                        const isDirectory = fs.lstatSync(domainPath).isDirectory()

                        if (isDirectory) {
                            certficates[domain] = {}

                            certficates[domain].key = fs.readFileSync(
                                path.join(certDir, domain, 'privkey.pem'),
                            )
                            certficates[domain].cert = fs.readFileSync(
                                path.join(certDir, domain, 'fullchain.pem'),
                            )
                        }
                    })

                    /// TODO: Change this to use as many certs for as many servers as needed
                    serverOpts = {
                        /// TODO: change this from using the passphrase to domain
                        cert: certficates[this.config.ssl.passphrase].cert,
                        key: certficates[this.config.ssl.passphrase].key,
                    }
                    break

                default:
                    serverOpts = {
                        cert: fs.readFileSync(this.config.ssl.certificateFilename, 'utf-8'),
                        key: fs.readFileSync(this.config.ssl.certificateKeyFilename, 'utf-8'),
                        // ca: fs.readFileSync(this.config.ssl.certificateAuthorityFilename, 'utf-8'),
                        passphrase: this.config.ssl.passphrase,
                    }
                    break
            }

            this.log.info(
                `configuring SSL using certificate information on port:${this.config.sslport}`,
                serverOpts,
            )

            this.app.set('sslport', this.config.sslport)
            return https.createServer(serverOpts, this.app)
        } catch (e) {
            this.log.error('error setting up ssl for app', {
                sslSetupError: e,
            })
        }
    }

    /// Adds development server debugging functionality
    __debug() {
        const reloadServer = reload(this.app)
        const watchPath = util.getRootPath('templates')

        if (fs.existsSync(watchPath)) {
            watch.watchTree(watchPath, (f, curr, prev) => {
                this.log('Asset change detected, reloading connection')
                reloadServer.reload()
            })
        } else {
            this.log.error('cannot watch because folder does not exist', {
                watchPath,
            })
        }
    }

    /**** runtime methods *****/
    /// Runs the express (wr)app with all of the middleware configured
    run(
        started = () => {
            this.log.info(
                `{${this.config.appName}} is listening on: http://${this.config.host}:${this.config.port}`,
            )
        },
    ) {
        this.log.info(`running sexpress on port`, this.config.port)

        this.app.set('port', this.config.port)
        let httpsServer = null,
            serverOpts = {}

        const httpServer = http.createServer(serverOpts, this.app)

        /// Load runtime modules
        if (
            !this.config.noSSL &&
            !!this.config.ssl &&
            (!!this.config.ssl.passphrase || !!this.config.ssl.strategy)
        ) {
            httpsServer = this.__ssl(serverOpts)
        }

        if (this.config.debug) {
            this.__debug()
        }

        const errorHandler = (error, message) => {
            message = `Encountered fatal error [${error.code}]${message ? ` - ${message}` : ''}: `
            switch (error.code) {
                case 'EADDRINUSE':
                    message += 'is there another server running on this port?'
                default:
                    this.log.error(message)
            }
        }

        if (!!httpServer) {
            httpServer
                .listen(this.app.get('port'), started)
                .on('error', (e) => errorHandler(e, 'HTTP server error'))
        }

        if (!!httpsServer) {
            httpsServer
                .listen(this.app.get('sslport'), started)
                .on('error', (e) => errorHandler(e, 'HTTPS server error'))
        }
    }

    renderSync(view, options) {
        /// Ensure the views path is set
        const viewFilePath = path.join(
            this.app.get('views'),
            view.replace(this.app.get('views'), ''),
        )
        let rendered

        this.sexyRenderer(viewFilePath, options, (err, _rendered) => {
            if (err) return null

            rendered = _rendered
        })

        return rendered
    }

    renderView(view, options, callback) {
        /// Ensure the views path is set
        const viewFilePath = path.join(
            this.app.get('views'),
            view.replace(this.app.get('views'), ''),
        )

        return this.sexyRenderer(viewFilePath, options, callback)
    }

    renderViewOrTemplate(view, data, res) {
        const viewFile = path.join(
            this.config.viewsFolder,
            `${view}.${this.config.overrideViewEngine}`,
        )

        if (fs.existsSync(viewFile)) {
            return res.render(view, data)
        }

        return this.renderTemplate(view.replace('/index', ''), data, res)
    }

    renderTemplate(template, data, res) {
        const pageTemplate = path.join(this.config.templatesFolder, template, 'index')
        const ejsTemplate = `${pageTemplate}.${this.config.overrideViewEngine}`
        const htmlTemplate = `${pageTemplate}.html`

        if (this.config.supportRendering && fs.existsSync(ejsTemplate)) {
            this.log.debug('rendering template', { data, ejsTemplate })

            res.locals.partials = path.join(this.config.controllersFolder, 'views', '/')
            return res.render(ejsTemplate, data)
        }

        if (fs.existsSync(htmlTemplate)) {
            this.log.debug('serving html file', htmlTemplate)
            return res.sendFile(htmlTemplate)
            /// TODO: Send data somehow?
        }

        this.log('could not render template', template)
    }

    sendEmail(subdomainConfig, opts = {}) {
        return _sendEmail(
            !!subdomainConfig ? subdomainConfig : this.config,
            opts.to,
            opts.subject,
            opts.text,
            opts.callback,
            opts.html,
            opts.from,
        )
    }
}

module.exports = Sexpress
