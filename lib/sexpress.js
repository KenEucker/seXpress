const express = require('express')
const session = require('express-session')
const path = require('path')
const fs = require('fs')
let config = require('clobfig')()

/// TODO: put these dependencies closer to their scopes
const bodyParser = require('body-parser')
const cookieSession = require('cookie-session')
const cookieParser = require('cookie-parser')
const nodemailer = require('nodemailer')
const favicon = require('serve-favicon')
const passport = require('passport')
const watch = require('watch')
const http = require('http')
const https = require('https')
const reload = require('reload')
const swaggerJSDoc = require('swagger-jsdoc')

/// Utilities
const util = require('./util')(config.AppRoot)
const debugFilename = util.getRootPath('config.debug.js')

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
    publicFields: {
        meta: true,
        images: true,
        page: true,
    },
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
        this.hooks = []
        this.controllers = []
        this.routes = []

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

        this.log.debug('Configuration set, beginning init', this.config)

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

        /// Initialize the application to send and recieve proper JSON
		this.initJSONResponse()
		
		this.initCookies(this.config.cookies)

        /// TODO: can this go into the authentication module?
        /// Initialize and configure passportjs for maintaining connections to third party auth's
        this.initPassport(this.config.passport, this.config.session)

        /// Discover and add the favicon
        this.initFavicon(this.config.publicFolder)
	}
	
	initCookies(cookieOpts = {}) {
		const domain = `.${this.config.host}`
		cookieOpts = cookieSession(util.merge({
			name: this.config.appName,
			key: this.config.appName,
			keys: ['domain', 'maxAge'],
			secret: this.config.security ? this.config.security.secret : this.config.appName,
			cookie: { domain, maxAge: 60 * 60 * 24 }
		}, cookieOpts))
 
		this.app.set('trust proxy', 1) // trust first proxy
		this.app.use(cookieParser())
		this.app.use(cookieOpts)

		this.log.debug('cookies set', {domain})
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
            'hooks',
            'api',
            'docs',
            'robots',
            'routing',
            'rendering',
            'templating',
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

        if (this.config.debug) {
            this.log.error = (m, o) => {
                console.trace(m, o)
            }
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

        Object.keys(this.config.subdomains).forEach((subdomain) => {
            if (_coreSubdomains.indexOf(subdomain) !== -1) {
                this.log.info('overriding core subdomain', subdomain)
            }
            const subdomainConfiguration = this.config.subdomains[subdomain]

            const mergedSubdomainConfiguration = util.merge(
                this.config.defaults,
                subdomainConfiguration,
            )

            // const getMergedSubdomainConfiguration = (config, fieldMap = {}) => {
            // 	Object.keys(fieldMap).forEach((field) => {
            // 		const copyAll = typeof fieldMap[field] === 'boolean' ? fieldMap[field] : false
            // 		const fields = copyAll ?
            // 			Object.keys(config[field] || {}) : fieldMap[field]

            // 		config[field] = util.getValuesFromObjectOrDefault(
            // 			fields,
            // 			config[field],
            // 			this.config.defaults,
            // 			this.config
            // 		)
            // 	})

            // 	return config
            // }

            // const subdomainAuthFields = {
            //     imgur: [
            //         'imgurClientID',
            //         'imgurClientSecret',
            //         'imgurCallbackURL',
            //         'imgurEmailAddress',
            //     ],
            //     s3: ['AwsCdnUrl', 'emailAddress', 'accessKeyId', 'secretAccessKey', 'region'],
            //     reddit: [
            //         'redditClientID',
            //         'redditClientSecret',
            //         'redditCallbackURL',
            //         'redditUserName',
            //         'redditUserAgent',
            //         'redditPassword',
            //     ],
            //     google: [
            //         'googleClientID',
            //         'googleClientSecret',
            //         'googleCallbackURL',
            //         'googleEmailAddress',
            //     ],
            //     email: [
            //         'emailAccountHost',
            //         'emailService',
            //         'emailAccountAddress',
            //         'emailAccountPassword',
            //         'emailAccountIsSecure',
            //         'emailAccountPort',
            // 	]
            // }
            // const subdomainAuthConfiguration = getMergedSubdomainConfiguration(subdomainConfiguration, subdomainAuthFields)
            this.authTokens[subdomain] = util.getValuesFromObjectOrDefault(
                ['imgur', 'google', 'reddit'],
                mergedSubdomainConfiguration,
            )

            // const subdomainPublicFields = getMergedSubdomainConfiguration(subdomainConfiguration, this.config.publicFields)

            // this.config.subdomains[subdomain] = util.merge(subdomainAuthFields, subdomainPublicFields)
            this.config.subdomains[subdomain] = mergedSubdomainConfiguration
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
        this._customRoutesAdded = []

        const prefix = `/${controller.prefix ? controller.prefix : root}`
        const viewsFolder = path.join(this.config.controllersFolder, root, 'views')
        const viewEngine = !!controller.engine ? controller.engine : this.config.overrideViewEngine
        const viewGeneratedRoutes = []

        const logControllerAction = (action, data) => {
            this.log.info(`[${controllerName}] -> ${action}`, data)
        }

        if (!root) {
            controller.useRootPath =
                typeof controller.useRootPath !== 'undefined' ? controller.useRootPath : true
        }

        /// generate routes based on existing view files
        /// Note: this happens before init, to allow the controller to modify its views
        if (fs.existsSync(viewsFolder)) {
            applet.set('views', viewsFolder)

            const viewFiles = util.getViews(this.config, viewsFolder)
            Object.keys(viewFiles).forEach((viewName) => {
                const filename = viewFiles[viewName]

                /// Only generate this view if the controller hasn't overridden the route
                if (!controller[viewName]) {
                    viewGeneratedRoutes[viewName] = filename
                    controller[viewName] = filename
                }
            })
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

        /// allow specifying the view engine
        logControllerAction(`engine [${viewEngine}]`)
        applet.set('view engine', viewEngine)

        if (controller.hooks && controller.hooks.length) {
            const hooks = Object.keys(controller.hooks)
            logControllerAction('registering hooks', hooks)
            hooks.forEach((endpoint) => {
                this.hook(endpoint, controller.hooks[endpoint])
            })
        }

        const controllerMethods = Object.keys(controller)
        /// generate routes based
        /// on the exported methods
        controllerMethods.forEach((key) => {
            // "reserved" exports
            if (['show', 'list', 'edit', 'update', 'create', 'index'].indexOf(key) === -1) {
                this.log.debug('ignoring', key)
                return
            }
            this.log.debug('adding controller method', key)

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
                    postfix = ''
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

                /// Set the view handler
                controller[key] = this.viewHandler(controller[key])
            } else if (routeIsTemplateMap) {
                pathMessage = `${pathMessage} :: [${controller[key]}]`

                /// Set the template handler
                controller[key] = this.templateHandler(controller[key])
            } else {
                pathMessage = `${pathMessage}()`
            }

            /// setup
            handler = this.requestHandler(controller[key])

            /// before middleware support
            if (controller.before) {
                applet[method](url, this.requestHandler(controller.before), handler)
            } else {
                applet[method](url, handler)
            }

            this.log.info('', [pathMessage])
        })

        /// middleware custom routes
        if (typeof controller.routes === 'function') {
            this._customControllerRoutePrefix = controller.useRootPath ? '' : prefix

            const thisApp = this.app
            /// use the applet for the controller routes
            this.app = applet
            controller.routes(this)
            /// reset back to the main app
            this.app = thisApp

            /// TODO: refactore this into a routes object that keeps track of all registered routes
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

        /// Hold onto the state of the controller
        this.controllers[controllerName] = controller

        /// mount the app
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
                this.log.debug(`Loading module`, {
                    name: modules[module].module,
                    description: modules[module].description,
                })
                modules[module].bind(this)()
            }
        }
    }

    getLoginUrl(req, subdomain) {
        let protocol,
            host,
            port = this.config.port

        if (typeof req === 'string') {
            host = this.config.host
            protocol = this.config.protocol
        } else {
            host = req.hostname
            const hostSubdomainEnd = host.indexOf('.') + 1
            host = host.substring(hostSubdomainEnd).replace('login.')
            protocol = req.protocol
        }

        return `${protocol}://login.${host}${port !== 80 ? `:${port}` : ''}`
    }

    isAuthenticatedHandler(failureRedirect) {
        return (req, res, next) => {
            if (!req.isAuthenticated()) {
                const activeAuthStrategies = this.config.security.schemes
                    ? this.config.security.schemes.map((s) => s.name || s)
                    : ['basic', 'local']

                /// Try all of the authentication methods
                return passport.authenticate(activeAuthStrategies, (err, user) => {
                    this.log.debug('exhausted authenticators', {
                        err,
                        user,
                        auth: req.headers.authorization,
                    })
                    if (!err && user) return next()

                    if (req.method === 'GET') {
                        failureRedirect = failureRedirect || this.getLoginUrl(req)

                        return res.redirect(failureRedirect)
                    } else {
                        return res.status(401).end()
                    }
                })(req, res, next)
            }

            next()
        }
    }

    apiRoute(endpoint, response, method) {
        const self = this

        const apiRouteValidator = function apiRouteValidator(sub, req, res, host, next) {
            console.log('checking api route', { sub, host })
            if (sub === 'api') {
                return self.requestHandler(response)(sub, req, res, host, next)
            }
        }
        const ignoreSubdomains = Object.keys(this.core).filter((m) => ['index'].indexOf(m) === -1)
        const subdomains = Object.keys(this.config.subdomains).filter(
            (s) => ignoreSubdomains.indexOf(s) === -1,
        )

        /// Add a route for each subdomain
        subdomains.forEach((subdomain) => {
            const subdomainApiRoute = `/${subdomain}${endpoint}`
            this.routes.push(subdomainApiRoute)

            console.log('confiuring', { subdomain, subdomainApiRoute, method })
            this.app[method](subdomainApiRoute, this.isAuthenticatedHandler(), apiRouteValidator)
        })
    }

    route(endpoint, response, methods = 'get', secure = false) {
        const routeIsApiEndpoint = this._customControllerRoutePrefix === '/api'
        methods = typeof methods === 'string' ? [methods] : methods
        const functionName = util.getFunctionName(response)

        methods.forEach((method) => {
            this._customRoutesAdded.push({ method, endpoint, functionName })

            if (secure || routeIsApiEndpoint) {
                console.log({
                    routeIsApiEndpoint,
                    endpoint,
                    prefix: this._customControllerRoutePrefix,
                })
                if (routeIsApiEndpoint) {
                    this.apiRoute(endpoint, response, method)
                }

                /// Add the non api route as well
                this.app[method](
                    `${this._customControllerRoutePrefix}${endpoint}`,
                    this.isAuthenticatedHandler(),
                    this.requestHandler(response),
                )
            } else {
                this.app[method](endpoint, this.requestHandler(response))
            }
        })
    }

    hook(endpoint, payload, overwriteExisting = false) {
        const endpointIsRegistered = this.hooks.indexOf(endpoint) !== -1

        if (typeof payload === 'function') {
            /// If the payload is a function, either
            if (!!endpointIsRegistered || (endpointIsRegistered && overwriteExisting)) {
                /// set/overwrite the registered hook with the payload
                this.hooks[endpoint] = payload
            } else {
                /// pass the registered hook to the payload to be called with custom opts
                return payload(this.hooks[endpoint])
            }
        } else if (typeof payload === 'object') {
            /// If the payload is an object, either
            const registeredEndpointIsFunction = endpointIsRegistered
                ? typeof this.hooks[endpoint] === 'function'
                : endpointIsRegistered
            if (endpointIsRegistered && registeredEndpointIsFunction) {
                /// call the registered hook with the payload
                this.hooks[endpoint](payload)
            } else {
                /// set/overwrite the registered hook with the payload
                this.hooks[endpoint] = payload
            }
        } else {
            this.log.error(
                `hook [${endpoint}] cannot be called or registered with the payload provided`,
                { payload, endpointIsRegistered },
            )
        }
    }

    isValidSubdomain(subdomain, validSubdomains, ignoreSubdomains = ['api', 'login']) {
        const coreModules = Object.keys(this.core).filter((m) => ignoreSubdomains.indexOf(m) === -1)
        const reject =
            !validSubdomains || !validSubdomains.length
                ? coreModules.indexOf(subdomain) !== -1
                : validSubdomains.indexOf(subdomain) === -1

        return reject
    }

    viewHandler(view) {
        return (subdomain, req, res, host) => {
            // if (!subdomain) {
            //     const hostSubdomainEnd = host.indexOf('.') + 1
            //     const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

            //     this.log.error({
            //         subdomain,
            //         hostNotFound: host,
            //         redirectToHost,
            //     })

            //     return res.redirect(redirectToHost)
            // }

            const params = typeof req.params === 'object' ? req.params : {}
            const data = this.getPublicConfig(subdomain, host, params)

            return res.render(view, data)
        }
    }

    templateHandler(template) {
        return (subdomain, req, res, host) => {
            if (!subdomain) {
                const hostSubdomainEnd = host.indexOf('.') + 1
                const redirectToHost = `${req.protocol}://${host.substring(hostSubdomainEnd)}`

                this.log.error('Subdomain not set, redirecting to host', {
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

    requestHandler(handler, subdomains, skipLogging = false) {
        const dontLog = [
            '/public*',
            '/css*',
            '/js*',
            '/font*',
            '/webfont*',
            '/img*',
            '/media*',
            '/docs*',
            '/api/swagger.json',
        ]

        return (req, res, next) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            if (this.isValidSubdomain(subdomain, subdomains)) {
                this.log.debug(
                    `request invalid for subdomain [${subdomain}]`,
                    // handler,
                    util.getFunctionName(handler),
                )
                return next()
            }

            const host = req.headers.host
            const url = req.url
            skipLogging = skipLogging ? skipLogging : new RegExp(dontLog.join('|')).test(url)

            if (!skipLogging) {
                const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress

                this.log.status(`[${req.method}] request`, {
                    handler: handler.name ? handler.name : util.getFunctionName(handler) || '*()',
                    url,
                    subdomain,
                    ip,
                    body:
                        ['options', 'get'].indexOf(req.method.toLocaleLowerCase()) === -1
                            ? req.body
                            : undefined,
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
    getPublicConfig(subdomain, host, overrides = {}) {
        const publicConfig = {
            loginUrl: this.getLoginUrl(subdomain),
            host,
            SUBDOMAIN: subdomain.toUpperCase(),
            thisSubdomain: subdomain,
            debug: this.config.debug,
            content: this.config.content,
            subdomains: [],
        }

        const fieldMap = this.config.publicFields
        Object.keys(this.config.subdomains).forEach((subdomainName) => {
            const subdomainInformation = this.config.subdomains[subdomainName]
            const customCssPath = path.join(__dirname, 'assets/css', `${subdomain}.css`)

            const pageData = {}

            Object.keys(fieldMap).forEach((fieldName) => {
                const defaults = this.config.defaults || {}
                const copyAll =
                    typeof fieldMap[fieldName] === 'boolean' ? fieldMap[fieldName] : false
                const fields = copyAll ? [fieldName] : fieldMap[fieldName]
                const merged = util.getValuesFromObjectOrDefault(
                    fields,
                    subdomainInformation,
                    overrides,
                    defaults,
                )

                pageData[fieldName] = merged[fieldName]
            })

            pageData.hasCustomCss = fs.existsSync(customCssPath)

            if (subdomain === subdomainName) {
                publicConfig.page = util.merge(pageData, overrides)
            }

            publicConfig.subdomains[subdomainName] = pageData
        })

        publicConfig.content = this.config.content

        return this.config.publicConfigFilter(publicConfig, this.config, subdomain)
    }

    getTemplateNameFromSubdomain(subdomain) {
        if (!!this.config.subdomains[subdomain]) {
            return this.config.subdomains[subdomain].template
        }

        return null
    }

    getSubdomainOpts(req) {
        const subdomain =
            (typeof req).toLocaleLowerCase() === 'string'
                ? req
                : util.getSubdomainPrefix(this.config, req, true)

        let subdomainConfig = {}

        if (!!this.config.subdomains[subdomain]) {
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
        const defaultOpenApiDefinition = {
            openapi: opts.openapi || '3.0.1',
            info: {
                title: opts.title || opts.appName,
                version: opts.version,
                description: opts.description,
                termsOfService: opts.tos,
                contact: {
                    email: opts.author,
                },
                license: opts.license,
            },
            externalDocs: {
                description: `Find out more about the ${opts.title || opts.appName} API`,
                url: util.getHostUri(opts, opts.host, undefined, '/api/docs', true),
            },
            // host: overrides.host || opts.host,
            servers: overrides.servers
                ? []
                : [
                      {
                          url: `http://${overrides.host || opts.host}`,
                      },
                  ],
        }
        const openApiDefinition = util.merge(
            opts.openApiDefinitionFile
                ? require(opts.openApiDefinitionFile)
                : defaultOpenApiDefinition,
            overrides,
        )

        if (opts.security.enabled) {
            const securitySchemes = {
                jwt: {
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
                const useTheseSchemesOnly = opts.security.schemes.map((s) => s.name || s)
                Object.keys(securitySchemes).forEach((strategy) => {
                    if (useTheseSchemesOnly.indexOf(strategy) === -1)
                        delete securitySchemes[strategy]
                })
            }

            const responses = {
                UnauthorizedError: {
                    description: 'User not authenticated',
                    schema: {
                        type: 'string',
                    },
                },
            }

            if (opts.security.enabled === 'all') {
                openApiDefinition.security = Object.keys(securitySchemes).reduce((o, s) => {
                    o[s] = []
                    return o
                }, {})
            }

            openApiDefinition.components = { securitySchemes, responses }
        }

        const swaggerDefinition = util.merge(openApiDefinition, opts.openApiDefinition || {})

        const jsDocOpts = {
            swaggerDefinition,
            apis: this.apis(),
        }
        return swaggerJSDoc(jsDocOpts)
    }

    apis() {
        const excludeTheseControllers = util.merge(
            Object.keys(this.core).filter((f) => f !== 'api'),
            this.config.privateApis || [],
        )
        const controllers = util.getControllers(
            this.config,
            this.config.controllersFolder,
            excludeTheseControllers,
        )

        return controllers
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

    initPassport(passportOpts = {}, sessionOpts = {}) {
        /// Set up request sessions
        this.app.use(
            session(
                util.merge(
                    {
                        secret: this.config.appName,
                        resave: true,
                        saveUninitialized: true,
                    },
                    sessionOpts,
                ),
            ),
        )

        /// Initialize passportjs
        this.app.use(passport.initialize(passportOpts))
        this.app.use(passport.session({}))
    }

    initMiddlewares(middlewares) {}

    initJSONResponse(urlencoded = true, spaces = 2) {
        /// Support JSON-encoded bodies
        this.app.set('json spaces', spaces)
        this.app.use(bodyParser.json())

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
    isSecure() {
        /// TODO: check for file access?
        return (
            !this.config.noSSL &&
            !!this.config.ssl &&
            (!!this.config.ssl.passphrase || !!this.config.ssl.strategy)
        )
    }

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

    /**** private methods *****/
    /// Protects connections to the server with an ssl certificate
    __ssl(serverOpts) {
        try {
            switch (this.config.ssl.strategy) {
                case 'letsencrypt':
                    const certDir = '/etc/letsencrypt/live'
                    if (fs.existsSync(certDir)) {
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

    /// The default renderer
    __renderer() {}

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
                `{${this.config.appName}} is listening on: ${this.config.protocol}://${this.config.host}:${this.config.port}`,
            )
        },
    ) {
        this.log.info(`running sexpress on port`, this.config.port)

        this.app.set('port', this.config.port)
        this.app.set('port', this.config.port)
        let httpsServer = null,
            serverOpts = {}

        const httpServer = http.createServer(serverOpts, this.app)

        /// Load runtime modules
        if (this.isSecure()) {
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
                    this.log.error('server start error', message)
            }
        }

        if (!!httpServer) {
            this.config.protocol = 'http'
            httpServer
                .listen(this.app.get('port'), started)
                .on('error', (e) => errorHandler(e, 'HTTP server error'))
        }

        if (!!httpsServer) {
            this.config.protocol = 'https'
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

        this.__renderer(viewFilePath, options, (err, _rendered) => {
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

        return this.__renderer(viewFilePath, options, callback)
    }

    renderViewOrTemplate(view, data, res) {
        const viewFile = path.join(
            this.config.viewsFolder,
            `${view}.${this.config.overrideViewEngine}`,
        )
        const viewFileIndex = path.join(
            this.config.viewsFolder,
            `${view}/index.${this.config.overrideViewEngine}`,
        )

        this.log.debug(`Searching for view [${view}]`, { viewFile, viewFileIndex })
        if (fs.existsSync(viewFile) || fs.existsSync(viewFileIndex)) {
            return res.render(view, data)
        }

        return this.renderTemplate(view.replace('/index', ''), data, res)
    }

    renderTemplate(template, data, res) {
        const pageTemplate = path.join(this.config.templatesFolder, template, 'index')
        const viewTemplate = `${pageTemplate}.${this.config.overrideViewEngine}`
        const htmlTemplate = `${pageTemplate}.html`

        this.log.debug(`Searching for template [${template}]`, {
            pageTemplate,
            viewTemplate,
            htmlTemplate,
        })
        if (this.config.supportRendering && fs.existsSync(viewTemplate)) {
            this.log.debug('rendering template', { data, viewTemplate })

            res.locals.partials = path.join(this.config.controllersFolder, 'views', '/')
            return res.render(viewTemplate, data)
        }

        if (fs.existsSync(htmlTemplate)) {
            this.log.debug('serving html file', htmlTemplate)
            return res.sendFile(htmlTemplate)
            /// TODO: Send data somehow?
        }
        this.log.error('could not render template', template)
        res.status(409).end()
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
