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
const { getQuestion, getPersonName } = require('random-questions')

/// LOAD CONFIGURATION
let config = require('clobfig')({
    /********** package json *********/
    title: '@title',
    version: '@version',
    subdomains: '@subdomains',
    defaults: '@defaults',
    description: '@description',

    /********** app defaults *********/
    name: '@name',
    appPhrase: getQuestion().replace(' i ', ' I '),
    host: 'localhost',
    port: 80,
	run: false,

    /********** module defaults *********/
    initSeqMessage: 'Sexy Configuration!',
    logging: {
        onlyLogErrors: true,
    },

    publicFilter: (c) => c,
    public: {
        meta: true,
        images: true,
        page: true,
    },
})

const util = require('./util')(config.AppRoot)
const debugFilename = util.getRootPath('config.debug.js')
const debug = !!config.debug
    ? config.debug
    : process.argv.reduce((out, arg) => (out = out || arg.indexOf('--debug=true') !== -1), false)

/// Configuration is first initialized here, upon import
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

class Sexpress {
    makeArt() {
        return new Promise((r) => {
            ;(function () {
                const asciiArt = require('ascii-art-image')
                const image = new asciiArt({ filepath: path.join(__dirname, 'sexpress.jpg') })
                image.write((err, converted) => {
                    console.log(err || converted)
                    r()
                })
            })()
        })
    }

    constructor(opts = {}) {
        /// powered by expressjs
        this.app = express()
        this._running = false

        /// internal memory store
        this.authTokens = { default: {} }
        this.customApiRoutes = []
        this.hooks = []
        this.controllers = []
        this.routes = []

        /// temporary variables
        this._customRoutesAdded = []
        this._customControllerRoutePrefix = ''

        const initPromised = debug ? this.makeArt() : Promise.resolve()

        /// Construct configuration from defaults, config files, and instantiation opts
        this.setConfiguration({
            ...config,
            ...opts,
		})

        /// TODO: don't allow initialization upon instantiation?
        /// energize
        this._initPromise = [initPromised.then(this.init.bind(this))]
    }

    /// Begin application initialization
    init() {
        return util.promiseMe(async (done) => {
            if (!this.config.modules) {
                const modulesFolderFiles = fs.readdirSync(path.join(__dirname, 'modules'))
                const modulesFiles = modulesFolderFiles.filter((f) => f.indexOf('.js') !== -1)

                this.config.modules = modulesFiles.map((m) => m.replace('.js', ''))
            }

            /// get the core modules
            this.core = require(path.join(__dirname, 'modules'))(this.config.modules)

            /// Always run the debug module, it sets up the logger, and if it is not present let the errors be thrown
            this.core.debug.bind(this)(debug)

            /// The logger is now ready for use
            this.log.debug(
                `\t\tI promise to ${this.config.run ? 'run' : 'wait'} all ${this.config.run ? 'day' : 'night'}.\n\t\t${
                    this.config.appPhrase
                }\n\n`,
            )
            this.log.status(`\n💃 sexpress -> {${this.config.name}} 💃\n`)
            this.log.debug(`🛰  sexpress core modules definition`, this.core)

            this.log.info(`\t🤖 \x1b[43m\x1b[30m Init \x1b[0m\x1b[0m 🤖`)

            /// Load core modules in this order
            await this.loadModules(this.core, [
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
                'rendering',
                'templating',
                'routing',
                'errors',
            ])

            /// Add third party middleware support
            this.initMiddlewares(this.config.middlewares)

            this.log.debug(`sexpress application {${this.config.name}} initialized`, this.config)

            /// engage?
            if (this.config.run) {
                return this.run().then(done)
            }

            done()
        })
    }

    initMiddlewares(middlewaresOpts = {}) {
        this.middlewares = util.merge(this.config.middlewares, middlewaresOpts)
        const middlewares = Object.keys(middlewaresOpts)

        if (middlewares.length) {
            const middlewareNotSupported = class middlewareNotSupported {
                constructor() {
                    return 'not supported'
                }
            }

            middlewares.forEach((middleware) => {
                const middlewareFileName = path.join(
                    this.config.folders.middlewaresFolder,
                    middleware,
                    '.js',
                )
                const middlewareClass = fs.existsSync(middlewareFileName)
                    ? require(middlewareFileName)
                    : middlewareNotSupported
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
            this.status = (m) => m
            this.log.debug = this.log.info = this.log.status = this.log.error = this.log
        }

        if (this.config.debug) {
            this.log.error = (m, o) => console.trace(m, o)
        } else {
            const infoLogWithoutData = this.log.info
            this.log.info = (m, o) => infoLogWithoutData(m)
        }
    }

    setConfiguration(config) {
        this.config = config
        this.coreSubdomains = this.config.coreSubdomains || [
            'api',
            'admin',
            'info',
            'status',
            'data',
            'content',
            'mail',
            'login',
        ]

        this.config.folders = this.config.folders || []
        this.config.defaults = this.config.defaults || {}

		const overrideMissingPackageJsonValues = (values = {}) => {
			Object.keys(values).forEach((key) => {
				this.config[key] = this.config[key] !== `@${key}` ? this.config[key] : values[key]
			})
		}

        const getThisOrDefaultOrRootFolder = (name, rootPath = '', strictlyPassed = false) => {
            rootPath =
                !strictlyPassed && (!rootPath || typeof rootPath !== 'array')
                    ? `${name.replace('Folder', '')}`
                    : rootPath

            return this.config.folders[name]
                ? this.config.folders[name]
                : util.getRootPath(rootPath)
        }

        this.config.folders.staticFolders = this.config.folders.staticFolders || []
        this.config.folders.appFolder = getThisOrDefaultOrRootFolder('appFolder', '')
        this.config.folders.publicFolder = getThisOrDefaultOrRootFolder('publicFolder')
        this.config.folders.contentFolder = getThisOrDefaultOrRootFolder('contentFolder', [
            'public',
            'content',
        ])
        this.config.folders.sslFolder = getThisOrDefaultOrRootFolder('sslFolder', ['config', 'ssl'])
        this.config.folders.templatesFolder = getThisOrDefaultOrRootFolder('templatesFolder')
        this.config.folders.controllersFolder = getThisOrDefaultOrRootFolder('controllersFolder')
        this.config.folders.viewsFolder = getThisOrDefaultOrRootFolder(
            'viewsFolder',
            path.join('controllers', 'views'),
            true,
        )
        this.config.getRootPath = util.getRootPath

        Object.keys(this.config.subdomains).forEach((subdomain) => {
            if (this.coreSubdomains.indexOf(subdomain) !== -1) {
                this.log.info('overriding core subdomain', subdomain)
            }
            const subdomainConfiguration = this.config.subdomains[subdomain]

            const mergedSubdomainConfiguration = util.merge(
                this.config.defaults,
                subdomainConfiguration,
            )

            this.authTokens[subdomain] = util.getValuesFromObjectOrDefault(
                ['imgur', 'google', 'reddit'],
                mergedSubdomainConfiguration,
            )
            this.config.subdomains[subdomain] = mergedSubdomainConfiguration
        })

        /// Configure SSL for a local file strategy
        const ssl = this.config.ssl || {}
        if (fs.existsSync(this.config.folders.sslFolder)) {
            const sslFiles = fs.readdirSync(this.config.folders.sslFolder)

            sslFiles.forEach((sslFile) => {
                const sslFileSplit = sslFile.split('.')
                const sslFileName = sslFileSplit[0]
                const sslFileExtension = path.extname(sslFile)

                if (sslFileExtension === '.pem') {
                    const sslFilePath = path.join(this.config.folders.sslFolder, sslFile)
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
        this.config.authentication =
            typeof this.config.authentication === 'object'
                ? this.config.authentication
                : {
                      enabled:
                          typeof this.config.authentication === 'undefined'
                              ? false
                              : this.config.authentication,
                  }

        const content = {}
        if (fs.existsSync(this.config.folders.contentFolder)) {
            const contentFiles = fs.readdirSync(this.config.folders.contentFolder)

            contentFiles.forEach((contentFile) => {
                const contentFileSplit = contentFile.split('.')
                const contentFileName = contentFileSplit[0]
                const contentFileExtension = path.extname(contentFile)

                if (contentFileExtension === '.html') {
                    const html = fs.readFileSync(
                        path.join(this.config.folders.contentFolder, contentFile),
                        {
                            encoding: 'utf8',
                        },
                    )
                    content[contentFileName] = html
                }
            })
		}
		
		overrideMissingPackageJsonValues({
			name: getPersonName(),
			version: "0.0.0-beta.0",
		})

        this.config.content = content
    }

    /**** application methods *****/
    registerController(controller, root = '') {
        const applet = express()

        root = controller.root ? controller.root : root
        const controllerName = root ? root : this.config.templating.indexControllerName

        this.log.info(`🪐 registering controller: <${controllerName}>`)
        this._customRoutesAdded = []

        const prefix = `/${controller.prefix ? controller.prefix : root}`
        const viewsFolder = path.join(this.config.folders.controllersFolder, root, 'views')
        const viewEngine = this.getDefaultViewEngine(controller.engine)
        const viewGeneratedRoutes = []

        const logControllerAction = (action, data) => {
            this.log.info(`✨  <${controllerName}> -> ${action}`, data)
        }

        if (!root) {
            controller.useRootPath =
                typeof controller.useRootPath !== 'undefined' ? controller.useRootPath : true
        }

        /// generate routes based on existing view files
        /// Note: this happens before init, to allow the controller to modify its views
        if (fs.existsSync(viewsFolder)) {
            logControllerAction(`linking views [${viewEngine}]`)
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
        applet.set('view engine', viewEngine)

        if (controller.hooks && controller.hooks.length) {
            const hooks = Object.keys(controller.hooks)
            logControllerAction(
                `registering hooks: ${util.consoleLogEmojiNumber(hooks.length)}`,
                hooks,
            )
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

            this.log.debug(`✨ ${pathMessage}`)
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

            if (this._customRoutesAdded.length) {
                logControllerAction(
                    `custom routes: ${util.consoleLogEmojiNumber(this._customRoutesAdded.length)}`,
                )
                this._customRoutesAdded.forEach((customRoute) => {
                    const { method, endpoint, functionName } = customRoute
                    this.log.debug(
                        '✨   ',
                        `[${method.toUpperCase()}] ${endpoint} -> ${
                            functionName ? functionName : '*'
                        }()`,
                    )
                })
            }

            this._customRoutesAdded = []
            this._customControllerRoutePrefix = ''
        }

        /// Hold onto the state of the controller
        this.controllers[controllerName] = controller

        /// mount the app
        this.app.use(applet)
    }

    setCoreSubdomain(subdomain) {
        const exists = this.coreSubdomains.indexOf(subdomain) !== -1

        if (!exists) {
            this.coreSubdomains.push(subdomain)
            return this.coreSubdomains
        }

        /// return false to indicate that the subdomain was already set
        return false
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

    async loadModules(modules, order) {
        return util.promiseMe(async (done) => {
            order = order || Object.keys(modules)

            if (modules) {
                for (let i = 0; i < order.length; ++i) {
					const module = order[i]
					const moduleDefaults = modules[module].defaults
					// const moduleIsEnabled = typeof moduleDefaults === 'boolean' && (moduleDefaults && moduleDefaults.enabled)
					
					/// Pass the default paramaeters as the initial state of the module
					const moduleInitPromise = modules[module].bind(this, moduleDefaults)()

					if (util.isPromise(moduleInitPromise)) {
						await moduleInitPromise
					}
                }
            }

            done()
        })
    }

    // authRoute(endpoint, response, methods = 'get', subdomains) {
    //     methods = typeof methods === 'string' ? [methods] : methods
    // 	const ignoreSubdomains = Object.keys(this.core).filter((m) => ['index'].indexOf(m) === -1)
    //     subdomains = Object.keys(subdomains).filter(
    //         (s) => ignoreSubdomains.indexOf(s) === -1,
    // 	)
    // 	/// Add a route for each subdomain
    //     // methods.forEach((method) => {
    //         const subdomainAuthRoute = `/auth/${endpoint.replace('/auth/', '')}`

    // 		console.log({subdomainAuthRoute, methods, subdomains})
    //         /// Add the external api rouest at api.{host}/{controller}
    //         methods.forEach((method) => {
    //             this.app[method](
    //                 subdomainAuthRoute,
    //                 this.requestHandler(response, subdomains),
    //             )
    //         })
    //     // })
    // }

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
            const data = this.getPublicData(subdomain, host, params)

            return res.render(view, data)
        }
    }

    templateHandler(template) {
        return (subdomain, req, res, host, next) => {
            if (!subdomain) {
                this.log.error('Subdomain not set for use with template, falling through', {
                    subdomain,
                    hostNotFound: host,
                })

                return next()
            }

            const params = typeof req.params === 'object' ? req.params : {}
            const data = this.getPublicData(subdomain, host, params)

            return this.renderTemplate(template, data, res)
        }
    }

    requestHandler(handler, subdomains, skipLogging = false) {
        return (req, res, next) => {
            const subdomain = util.getSubdomainPrefix(this.config, req)
            const subdomainIsIndex = subdomain === this.config.templating.indexControllerName
            if (!this.isValidSubdomain(subdomain, subdomains)) {
                if (!this.config.templating.headless || subdomainIsIndex) {
                    return next()
                }

                this.log.error(`🛑 request invalid for subdomain [${subdomain}]`, {
                    handler,
                    handlerName: util.getFunctionName(handler),
                    subdomain,
                    subdomains,
                    url: req.url,
                    host: req.hostname,
                    subdomains: req.subdomains,
                })
                return res.redirect(this.getBaseUrl())
            }

            const host = this.getHost()
            const url = req.url
			skipLogging = typeof skipLogging !== 'undefined' ? skipLogging : false
			skipLogging = skipLogging || new RegExp(this.config.logging.ignoreRoutes.join('|')).test(url)

            if (!skipLogging || this.config.debug) {
                const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress
                const reqIsOptionOrGet =
                    ['options', 'get'].indexOf(req.method.toLocaleLowerCase()) !== -1
                this.log.status(` ${reqIsOptionOrGet ? `👆` : `👇`} [${req.method}] request`, {
                    handler: handler.name ? handler.name : util.getFunctionName(handler) || '*()',
                    url,
                    subdomain,
                    ip,
                    body: !reqIsOptionOrGet ? req.body : undefined,
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

    getApis() {
        const excludeTheseControllers = util.merge(
            Object.keys(this.core).filter((f) => f !== 'api'),
            this.config.privateApis || [],
        )
        const controllers = util.getControllers(
            this.config,
            this.config.folders.controllersFolder,
            excludeTheseControllers,
        )

        return controllers
    }

    getAvilableSSOProviders(subdomain) {
        const ssoProviders = []

        let securtiyOpts = this.config.subdomains[subdomain].authentication
        /// TODO: change this to an option for login subdomains?
        if (!securtiyOpts) {
            securtiyOpts = this.config.authentication
        }

        if (securtiyOpts.imgur && securtiyOpts.imgur.imgurClientID) {
            ssoProviders.push('imgur')
        }
        if (securtiyOpts.reddit && securtiyOpts.reddit.redditClientID) {
            ssoProviders.push('reddit')
        }
        if (securtiyOpts.google && securtiyOpts.google.googleClientID) {
            ssoProviders.push('google')
        }

        return ssoProviders
    }

    getBaseUrl(host, protocol, subdomain, fullHost) {
        return util.getHostBaseUrl(this.config, host, protocol, subdomain, fullHost)
    }

    getCoreOpts(moduleName = '', overrides = {}, initial) {
		let defaults = initial

		if (typeof initial === 'undefined' && typeof overrides === 'boolean') {
			defaults = overrides
			overrides = {}
		}

        if (typeof defaults === 'boolean') {
            defaults = {
                enabled: defaults,
            }
		} else if (!defaults) {
			defaults = {
				enabled: typeof initial === 'boolean' ? initial : true,
			}
		}

		const fromConfig = typeof this.config[moduleName] === 'boolean' ? { enabled: this.config[moduleName] } : (typeof this.config[moduleName] === 'undefined' ? {} : this.config[moduleName])
        const moduleOpts = util.merge.all([defaults, fromConfig, overrides])
		this.log.debug(`initialized core module options for [${moduleName}]`, { initial, defaults, fromConfig, overrides, moduleOpts })

        return moduleOpts
    }

    getDefaultViewEngine(override) {
        if (override) return override

        const trueDefault = 'ejs'

        if (this.config.rendering && this.config.rendering.overrideViewEngine) {
            if (
                typeof this.config.rendering.overrideViewEngine === 'object' ||
                typeof this.config.rendering.overrideViewEngine === 'array'
            ) {
                return this.config.rendering.overrideViewEngine[0]
            }

            return this.config.rendering.overrideViewEngine
        } else if (typeof this.config.rendering === 'boolean' && this.config.rendering) {
            return this.config.rendering.overrideViewEngine
        }

        return trueDefault
    }

    getHomeUrl(req, path) {
        if (this.config.templating.headless && this.config.templating.home) {
            path = this.config.templating.home
        }
        path = path ? `/${path}` : ''
        return `${req.protocol}://${req.get('host')}${path}`
    }

    getHost(req) {
        /// TODO: normalize this response so that it is idempotent
        if (!req) return this.config.host

        return req.headers.host
    }

    getLoginUrl(req = {}, subdomain, ignoreSubdomains = []) {
        subdomain = subdomain && ignoreSubdomains.indexOf(subdomain) !== -1 ? '' : subdomain

        let loginHost = req.hostname
        const loginPath = subdomain !== 'login' ? '/login' : ''
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

        return loginUrl
    }

    /// TODO: refactor this method to not run on every request, this is a good candidate for implementing the app cache
    getPublicData(subdomain, host, overrides = {}) {
        const publicConfig = {
            loginUrl: this.getLoginUrl({ hostname: host }, subdomain, Object.keys(this.core)),
            host,
            SUBDOMAIN: subdomain.toUpperCase(),
            thisSubdomain: subdomain,
            debug: this.config.debug,
            content: this.config.content,
            subdomains: [],
        }

        const fieldMap = this.config.public
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

        return this.config.publicFilter(publicConfig, this.config, subdomain)
    }

    getSubdomainOpts(req) {
        const isString = (typeof req).toLocaleLowerCase() === 'string'
        const subdomain = isString ? req : util.getSubdomainPrefix(this.config, req)

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

    getSubdomainTemplateMaps(filterOutUndefined = true) {
        const getSubdomainAndTemplate = (out, subdomain) => {
            const { aliases, template } = this.config.subdomains[subdomain]
            if (!filterOutUndefined || (filterOutUndefined && !!template)) {
                out[subdomain] = template

                if (aliases && aliases.length) {
                    aliases.forEach((alias) => (out[alias] = template))
                }
            }

            return out
        }
        const subdomains = Object.keys(this.config.subdomains)
        const subdomainMappedTemplates = subdomains.reduce(getSubdomainAndTemplate, {})

        return subdomainMappedTemplates
    }

    getSwaggerSpec(opts, overrides = {}) {
        const defaultOpenApiDefinition = {
            openapi: opts.openapi || '3.0.1',
            info: {
                title: opts.title || opts.name,
                version: opts.version,
                description: opts.description,
                termsOfService: opts.tos,
                contact: {
                    email: opts.author,
                },
                license: opts.license,
            },
            externalDocs: {
                description: `Find out more about the ${opts.title || opts.name} API`,
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

        if (opts.authentication.enabled) {
            const securitySchemes = {
                jwt: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'Bearer',
                },
                basic: {
                    type: 'http',
                    scheme: 'basic',
                },
            }

            if (opts.authentication.schemes) {
                const useTheseSchemesOnly = opts.authentication.schemes.map((s) => s.name || s)
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

            if (opts.authentication.enabled === 'all') {
                openApiDefinition.authentication = util.merge(
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

    getUserData(req, subdomain, host) {
        const userData = {
            credentials: req.user,
            host: host || this.getHost(req),
            name: this.config.name,
            appPhrase: this.config.appPhrase,
            loginUrl: this.getLoginUrl(req, subdomain),
            sso: this.getAvilableSSOProviders(subdomain),
        }

        return userData
    }

    /**** validator methods *****/
    isAuthenticatedHandler(failureRedirect) {
        return (req, res, next) => {
            if (!req.isAuthenticated()) {
                const activeAuthStrategies = this.config.authentication.schemes
                    ? this.config.authentication.schemes.map((s) => s.name || s)
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

    isRunning() {
        return this._running
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
        const subdomain = util.getSubdomainPrefix(this.config, req)
        const subdomainPrefix = `${
            subdomain == this.config.templating.indexControllerName ? '' : `${subdomain}.`
        }`
        const path = ''
        const protocol = req.protocol
        const reconstructedUrl = `${protocol}://${subdomainPrefix}${host}${path}`

        const localhostPortIsTheSameForDebugging =
            origin === reconstructedUrl || origin === `${reconstructedUrl}:${this.config.port}`
        const originIsCorrectSubdomain = origin == `${protocol}://${subdomainPrefix}${host}`
        const originIsValid = originIsCorrectSubdomain || localhostPortIsTheSameForDebugging

        if (originIsValid) {
            this.log.debug(`✅  origin ${origin} is valid`)
        } else {
            this.log.error(`❗️  origin ${origin} is not valid`, {
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
        const subdomainIsCoreModule = coreModules.indexOf(subdomain) !== -1
        const hasRestrictedSubdomains = !(!validSubdomains || !validSubdomains.length)
        const isNotRestricted = hasRestrictedSubdomains && validSubdomains.indexOf(subdomain) === -1

        const reject = hasRestrictedSubdomains ? isNotRestricted : subdomainIsCoreModule

        return !reject
    }

    /**** runtime methods *****/
    /// Runs the express (wr)app with all of the middleware configured
    run(
        started = () => {
            this.log.status(
                `\n💃 {${this.config.name}} @ ${this.config.protocol}://${this.config.host}:${this.config.port} 💃 \n\n`,
            )
        },
    ) {
        /// We promised we would initialize first
        return Promise.all(this._initPromise).then(() => {
            this.log.debug(`I fullfilled all of my promises, now. ${this.config.appPhrase}`)
            this.log.info(`\t🤖 \x1b[42m\x1b[30m Ready \x1b[0m\x1b[0m 🤖`)

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
                message = `❗️  Encountered fatal error [${error.code}]${
                    message ? ` - ${message}` : ''
                }: `
                switch (error.code) {
                    case 'EADDRINUSE':
                        message += 'is there another server running on this port?'
                    default:
                        this.log.error('server start error', message)
                }

                this._running = false
            }

            if (!!httpServer) {
                this.config.protocol = 'http'
                httpServer
                    .listen(this.app.get('port'), started)
                    .on('error', (e) => errorHandler(e, 'FATAL ❗️ HTTP server error'))
            }

            if (!!httpsServer) {
                this.config.protocol = 'https'
                httpsServer
                    .listen(this.app.get('sslport'), started)
                    .on('error', (e) => errorHandler(e, 'FATAL ❗️ HTTPS server error'))
            }

            this._running = true
        })
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
        const findViewFile = (engine) => {
            const viewFile = path.join(this.config.folders.viewsFolder, `${view}.${engine}`)
            const viewFileIndex = path.join(
                this.config.folders.viewsFolder,
                `${view}/index.${engine}`,
            )

            this.log.debug(`Searching for view [${view}]`, { viewFile, viewFileIndex })
            return fs.existsSync(viewFile) || fs.existsSync(viewFileIndex)
        }

        let foundView = false
        if (
            (typeof engine === 'undefined' &&
                typeof this.config.rendering.overrideViewEngine === 'array') ||
            typeof this.config.rendering.overrideViewEngine === 'array'
        ) {
            this.config.rendering.overrideViewEngine.forEach((engine) => {
                foundView = findViewFile(engine)
                if (foundView) return false
            })
        } else {
            foundView = findViewFile(this.config.rendering.overrideViewEngine)
        }
        if (foundView) {
            res.render(view, data)
        }

        return this.renderTemplate(view.replace('/index', ''), data, res)
    }

    renderTemplate(template, data, res, engine) {
        engine = engine || this.config.rendering.overrideViewEngine

		if (!template) {
			// if (!this.config.templating.indexControllerName) {
				this.log.error('cannot render template', { template, engine })
				return res.redirect(this.getBaseUrl())
			// }

			// template = this.config.templating.indexControllerName
			// this.log.status('no template set for domain, providing index', { template, engine })
        }

        if (typeof engine === 'array') {
            let index = 0,
                success = false
            while (
                index < engine.length &&
                !(success = this.renderTemplate(template, data, res, engine[index]))
            ) {
                index++
            }

            /// if
            if (!(index < engine.length)) {
                this.log.error('could not render template', template)
                return res.status(409).end()
            }

            return success
        }

        const pageTemplate = path.join(this.config.folders.templatesFolder, template, 'index')
        const viewTemplate = `${pageTemplate}.${this.config.rendering.overrideViewEngine}`
        const htmlTemplate = `${pageTemplate}.html`

        this.log.debug(`Searching for template [${template}]`, {
            pageTemplate,
            viewTemplate,
            htmlTemplate,
        })
        if (this.config.rendering.enabled && fs.existsSync(viewTemplate)) {
            this.log.debug('rendering template', { data, viewTemplate })

            res.locals.partials = path.join(this.config.folders.controllersFolder, 'views', '/')
            res.render(viewTemplate, data)
            return true
        }

        if (fs.existsSync(htmlTemplate)) {
            this.log.debug('serving html file', htmlTemplate)
            res.sendFile(htmlTemplate)
            return true

            /// TODO: Send data somehow?
        }

        return false
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
