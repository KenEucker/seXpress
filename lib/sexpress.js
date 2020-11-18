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
        this.hooks = []

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
        this.initPassport(this.config.passport, this.config.session)

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
            'hooks',
            'robots',
            'routing',
            'rendering',
            'templating',
            'api',
            'docs',
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
        const viewsFolder = path.join(this.config.controllersFolder, root, 'views')
        const viewEngine = !!controller.engine ? controller.engine : this.config.overrideViewEngine
        const viewGeneratedRoutes = []
        const controllerMethods = Object.keys(controller)

        const logControllerAction = (action, data) => {
            this.log.info(`[${controllerName}] -> ${action}`, data)
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
        if (fs.existsSync(viewsFolder)) {
            applet.set('views', viewsFolder)

            const viewFiles = util.getViews(this.config, viewsFolder)
            Object.keys(viewFiles).forEach((viewName) => {
                const filename = viewFiles[viewName]

                if (!controller[viewName]) {
                    viewGeneratedRoutes[viewName] = filename

                    controller[viewName] = (s, r, res) => {
                        return res.render(filename)
                    }
                }
            })
        }

        if (controller.hooks && controller.hooks.length) {
            const hooks = Object.keys(controller.hooks)
            logControllerAction('registering hooks', hooks)
            hooks.forEach((endpoint) => {
                this.hook(endpoint, controller.hooks[endpoint])
            })
        }

        // generate routes based
        // on the exported methods
        for (const key in controllerMethods) {
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
                this.log.debug(`Loading module`, {
                    name: modules[module].module,
                    description: modules[module].description,
                })
                modules[module].bind(this)()
            }
        }
    }

    getLoginUrl(req, subdomain) {
        if (typeof req === 'string') {
            subdomain = req
            req = {
				protocol: this.config.protocol,
            }
        }
        let host = req.hostname || subdomain
		const hostSubdomainEnd = host.indexOf('.') + 1
		const redirectToHost = host.substring(hostSubdomainEnd).replace('login.')

        return `${req.protocol}://login.${redirectToHost}${
            this.config.port !== 80 ? `:${this.config.port}` : ''
        }`
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

    route(endpoint, response, methods = 'get', secure = false) {
        endpoint = `${this._customControllerRoutePrefix}${endpoint}`
        methods = typeof methods === 'string' ? [methods] : methods
        const functionName = util.getFunctionName(response)

        methods.forEach((method) => {
            this._customRoutesAdded.push({ method, endpoint, functionName })

            if (secure) {
                this.app[method](
                    endpoint,
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
        ]

        const checkSubdomains = (subdomain) => {
            if (subdomain === 'index' && !subdomains) return false

            const coreModules = Object.keys(this.core).filter((m) => m !== 'api')
            let reject = false
            if (!subdomains || !subdomains.length) {
                reject = coreModules.indexOf(subdomain) === -1
            } else {
                reject = subdomains.indexOf(subdomain) === -1
            }

            return reject
        }

        return (req, res, next) => {
			const subdomain = util.getSubdomainPrefix(this.config, req)
            if (checkSubdomains(subdomain)) {
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

    // setCoreApplet(applet) {
    // 	if (!this._main) throw new Error("Core applet cannot be set before get")

    // 	if (applet) {
    // 		this._main.use(applet)
    // 	}

    // 	this.app = this._main
    // 	this._main = null
    // }

    // getCoreApplet(opts = {}) {
    // 	if (this._main) throw new Error("Cannot set another core applet")

    // 	this._main = this.app
    // 	opts = opts || {
    // 		config: this.config,
    // 		app: this.app,
    // 		log: this.log,
    // 	}

    // 	return this.app = this.core.rendering.bind(express())(opts.config, opts.app, opts.log)
    // }

    /// TODO: refactor this method to not run on every request, this is a good candidate for implementing the app cache
    getPublicConfig(subdomain, host, overrides) {
        const publicConfig = {
			loginUrl: this.getLoginUrl(subdomain),
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
                this.config.publicFields || [],
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
			opts.openApiDefinitionFile ? require(opts.openApiDefinitionFile) : defaultOpenApiDefinition,
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
            apis: util.getControllers(opts, undefined, opts.privateApis),
        }
        return swaggerJSDoc(jsDocOpts)
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
                this.log.debug(
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
                    this.log.error(message)
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
        this.log.error('could not render template', template)
        res.status(409).header('location').end()
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
