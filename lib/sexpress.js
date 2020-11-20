const fs = require('fs')
const path = require('path')
const express = require('express')
const http = require('http')
const https = require('https')
const watch = require('watch')
const reload = require('reload')

/// TODO: put these dependencies closer to their scopes
const nodemailer = require('nodemailer')
const passport = require('passport')
const swaggerJSDoc = require('swagger-jsdoc')

/// Utilities
let config = require('clobfig')({
	"title": "@title",
	"version": "@version",
	"subdomains": "@subdomains",
	"defaults": "@defaults",
})
const util = require('./util')(config.AppRoot)
const debugFilename = util.getRootPath('config.debug.js')

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

/// Defaults
const _coreSubdomains = ['api', 'admin', 'info', 'status', 'data', 'content', 'mail', 'login']
const _defaults = {
    host: 'localhost',
    port: 80,
	run: false,
	onlyLogErrors: true,
	
    publicConfigFilter: (c) => c,
    publicFields: {
        meta: true,
        images: true,
        page: true,
	},
	
	initSeqMessage: 'Sexy Configuration!',
    indexControllerName: 'index',
    styleEngine: 'scss',
    overrideViewEngine: 'ejs',
	
	security: false,
	api: true,

	appName: config.appName || config.title,
	version: 'null',
	title: 'sexpress',
	description: 'an express application',
}

class Sexpress {
    constructor(opts = {}) {
        /// powered by expressjs
        this.app = express()

        /// internal memory store
        this.authTokens = { default: {} }
        this.customApiRoutes = []
        this.hooks = []
        this.controllers = []
        this.routes = []

        /// temporary variables
        this._customRoutesAdded = []
        this._customControllerRoutePrefix = ''

        /// Construct configuration from defaults, config files, and instantiation opts
        this.setConfiguration({
            ..._defaults,
            ...config,
            ...opts,
		})
		
        /// energize
        this.init()

        /// engage?
        if (this.config.run) this.run()
    }

    /// Begin application initialization
    init() {
        /// Set up the logger
        this.setLogger(util.log.setDebugging(this.config.debug))

		this.log.debug(`initializing sexpress application {${this.config.appName}}`, this.config)

        /// Load core modules
        this.initCoreModules()

        /// Add third party middleware support
        this.initMiddlewares(this.config.middlewares)
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
		
		this.log.debug('core modules defninition', this.core)

        /// Load core modules in this order
        this.loadModules(this.core, [
            'cache',
            'session',
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
	
	initMiddlewares(middlewaresOpts = {}) {
		this.middlewares = util.merge(this.config.middlewares, middlewaresOpts)
		const middlewares = Object.keys(middlewaresOpts)

		if (middlewares.length) {
			const middlewareNotSupported = class middlewareNotSupported {
				constructor() {
					return "not supported"
				}
			}

			middlewares.forEach((middleware) => {
				const middlewareFileName = path.join(this.config.middlewaresFolder, middleware, '.js')
				const middlewareClass = fs.existsSync(middlewareFileName) ? require(middlewareFileName) : middlewareNotSupported
				this.middlewares[middleware] = new middlewareClass()
			})
		}
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
		
		if (!this.config.title || this.config.title === "@title") {
			this.config.title = this.config.appName
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

    apiRoute(endpoint, response, methods = '') {
        methods = typeof methods === 'string' ? [methods] : methods

        const ignoreSubdomains = Object.keys(this.core).filter((m) => ['index'].indexOf(m) === -1)
        const subdomains = Object.keys(this.config.subdomains).filter(
            (s) => ignoreSubdomains.indexOf(s) === -1,
        )

        /// Add a route for each subdomain
        subdomains.forEach((subdomain) => {
            const subdomainApiRoute = `${subdomain === 'index' ? '' : `/${subdomain}`}${endpoint}`
            const internalApiRoute = `${
                this._customControllerRoutePrefix === 'api'
                    ? ''
                    : `/${this._customControllerRoutePrefix}`
            }${endpoint}`

            /// Only add the external routes
            this.routes.push(subdomainApiRoute)

            /// Add the external api rouest at api.{host}/{controller}
            methods.forEach((method) => {
                this.app[method](
                    subdomainApiRoute,
                    this.isAuthenticatedHandler(),
                    this.requestHandler(response, ['api']),
                )
            })

            /// Add the internal route
            methods.forEach((method) => {
                this.app[method](
                    internalApiRoute,
                    this.isAuthenticatedHandler(),
                    this.requestHandler(response),
                )
            })
        })
    }

    route(endpoint, response, methods = 'get', secure = false, subdomains) {
        const routeIsApiEndpoint = this._customControllerRoutePrefix === '/api'
        methods = typeof methods === 'string' ? [methods] : methods
        const functionName = util.getFunctionName(response)

        // console.log({endpoint, subdomains})
        methods.forEach((method) => {
            this._customRoutesAdded.push({ method, endpoint, functionName })

            if (routeIsApiEndpoint) {
                this.apiRoute(endpoint, response, method)
            } else if (secure) {
                /// Add the non api route as well
                this.app[method](
                    `${this._customControllerRoutePrefix}${endpoint}`,
                    this.isAuthenticatedHandler(),
                    this.requestHandler(response, subdomains),
                )
            } else {
                this.app[method](endpoint, this.requestHandler(response, subdomains))
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

    viewHandler(view) {
        return (subdomain, req, res, host) => {
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
                this.log.error(`request invalid for subdomain [${subdomain}]`, {
                    handler,
                    handlerName: util.getFunctionName(handler),
                    subdomain,
                    subdomains,
                    url: req.url,
                    host: req.hostname,
                    subdomains: req.subdomains,
                })
                return next()
            }

            const host = req.headers.host
            const url = req.url
            skipLogging = skipLogging ? skipLogging : new RegExp(dontLog.join('|')).test(url)

            if (!skipLogging) {
                const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress

                // console.trace({subdomains, subdomain})
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

            // console.log({subdomain, host})

            return handler.call({ app: this }, subdomain, req, res, host, next)
        }
    }

    /**** getter methods *****/
    /// Only returns the keyvals stored in the app
    get(name = '') {
        this.app.get(name)
    }

    getApis() {
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
	
	getAvilableSSOProviders(subdomain) {	
		const sso = []

		let subdomainInformation = this.config.subdomains[subdomain]
		/// TODO: change this to an option for login subdomains?
		if (subdomain === 'api' || subdomain === 'login') {
			subdomainInformation = this.config.defaults
		}

		if (subdomainInformation.imgur && subdomainInformation.imgur.imgurClientID) {
			sso.push('imgur')
		}
		if (subdomainInformation.reddit && subdomainInformation.reddit.redditClientID) {
			sso.push('reddit')
		}
		if (subdomainInformation.google && subdomainInformation.google.googleClientID) {
			sso.push('google')
		}

		return sso
	}

    /// TODO: refactor this method to not run on every request, this is a good candidate for implementing the app cache
    getPublicConfig(subdomain, host, overrides = {}) {
        const publicConfig = {
            loginUrl: this.getLoginUrl({ hostname: host }, subdomain, Object.keys(this.core)),
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

    getLoginUrl(req = {}, subdomain, ignoreSubdomains = []) {
        subdomain = subdomain && ignoreSubdomains.indexOf(subdomain) !== -1 ? '' : subdomain

        let loginHost = req.hostname
        const loginPath = subdomain ? '/login' : ''
        const protocol = req.protocol || this.config.protocol
        const port = this.config.port !== 80 ? `:${this.config.port}` : ''

        if (subdomain === 'index') {
            loginHost = this.config.host
        } else if (subdomain) {
            loginHost = `${subdomain}.${this.config.host}`
        } else {
            loginHost = `login.${loginHost.substring(loginHost.indexOf('.') + 1).replace('login.')}`
        }

        const loginUrl = `${protocol}://${loginHost}${port}${loginPath}`

        // console.trace({subdomain, hostname: req.hostname, url: req.url, loginUrl, ignoreSubdomains})
        return loginUrl
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

    getSwaggerSpec(opts, overrides = {}) {
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
                url: util.getHostUri(opts, opts.host, undefined, opts.api.docsEndpoint, true),
            },
            servers: overrides.servers
                ? []
                : [
                      {
                          url: `http://${overrides.host || opts.host}`,
                      },
                  ],
        }

        const openApiDefinition = util.merge(
            opts.openApiDefinitionFile ? opts.openApiDefinitionFile : defaultOpenApiDefinition,
            opts.openApiDefinition || {},
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

            const schema = {}

            const responses = {
                UnauthorizedError: {
                    description: 'User not authenticated',
                    schema: {
                        type: 'string',
                    },
                },
                Success: {
                    description: 'Success',
                    schema: {
                        type: 'string',
                    },
                },
                Found: {
                    description: 'Resource Found',
                    schema: {
                        type: 'string',
                    },
                },
                Error: {
                    description: 'Unknown Error',
                    schema: {
                        type: 'string',
                    },
                },
            }

            const requestBodies = {
                jsonRequestBody: {
                    content: {
                        'multipart/form-data': {
                            schema: 'object',
                        },
                    },
                },
            }

            if (opts.security.enabled === 'all') {
                openApiDefinition.security = util.merge(
                    Object.keys(securitySchemes).reduce((o, s) => {
                        o[s] = []
                        return o
                    }, {}),
                )
            }

            openApiDefinition.components = { securitySchemes, responses, schema, requestBodies }
        }

        const swaggerDefinition = util.merge(openApiDefinition, overrides)

        const jsDocOpts = {
            swaggerDefinition,
            apis: this.getApis(),
        }
        return swaggerJSDoc(jsDocOpts)
    }

    getTemplateNameFromSubdomain(subdomain) {
        if (!!this.config.subdomains[subdomain]) {
            return this.config.subdomains[subdomain].template
        }

        return null
    }

    /**** validator methods *****/
    isAuthenticatedHandler(failureRedirect) {
        return (req, res, next) => {
            if (!req.isAuthenticated()) {
                const activeAuthStrategies = this.config.security.schemes
                    ? this.config.security.schemes.map((s) => s.name || s)
                    : ['basic', 'local']

                /// Try all of the authentication methods
                return passport.authenticate(activeAuthStrategies, (err, user) => {
                    if (!err && user) return next()

                    this.log.debug('exhausted authenticators', {
                        err,
                        user,
                        auth: req.headers.authorization,
                    })

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

    isValidSubdomain(subdomain, validSubdomains, ignoreSubdomains = ['api', 'login']) {
        const coreModules = Object.keys(this.core).filter((m) => ignoreSubdomains.indexOf(m) === -1)
        const reject =
            !validSubdomains || !validSubdomains.length
                ? coreModules.indexOf(subdomain) !== -1
                : validSubdomains.indexOf(subdomain) === -1

        return reject
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

		if (this.config.debug) {
			this.__debug()
		}

        const httpServer = http.createServer(serverOpts, this.app)

        /// Load runtime modules
        if (this.isSecure()) {
            httpsServer = this.__ssl(serverOpts)
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

    /// TODO: put this into a plugin or something
    sendEmail(subdomainConfig, opts = {}) {
		return this.middlewares.email.sendEmail(
            !!subdomainConfig ? subdomainConfig : this.config,
            opts.to,
            opts.subject,
            opts.text,
            opts.callback,
            opts.html,
            opts.from,
        )
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
    __renderer() {
        /// TODO: this should probably return something
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
}

module.exports = Sexpress
