const fs = require('fs')
const path = require('path')
const express = require('express')
const http = require('http')
const watch = require('watch')
const reload = require('reload')
const proxy = require('express-http-proxy')
const redirect = require('express-redirect')

/// TODO: put these dependencies closer to their scopes
const swaggerJSDoc = require('swagger-jsdoc')
const { getQuestion, getPersonName } = require('random-questions')
const { rword } = require('rword')

class Sexpress {
    makeArt() {
        return new Promise((r) => {
            ;(() => {
                // const asciiArt = require('ascii-art-image')
                // const image = new asciiArt({ filepath: path.join(__dirname, 'sexpress.jpg') })
                // image.write((err, converted) => {
                //     console.log(err || converted)
                //     r()
                // })
                const tryRequire = require('try-require')
                const { dirname, join } = require('path')
                const merge = require('deepmerge')
                const sexpressPackageJson = tryRequire.resolve('sexpress/package.json')
                    ? require('sexpress/package.json')
                    : {
                          version: 'development',
                      }
                const packageJsonPath = join(dirname(require.main.filename), 'package.json')
                const packageJson = merge(
                    {
                        name: 'seXpress',
                        version: '0.0.0',
                        description: '',
                    },
                    tryRequire.resolve(packageJsonPath) ? require(packageJsonPath) : {},
                )

                const asciiArtLogo = require('asciiart-logo')
                console.log(
                    asciiArtLogo({
                        name: packageJson.name,
                        font: 'Colossal',
                        upperCase: false,
                    })
                        .emptyLine()
                        .left(packageJson.description)
                        .emptyLine()
                        .right(`version ${packageJson.version}`)
                        .emptyLine()
                        .right(
                            sexpressPackageJson
                                ? `seXpress version ${sexpressPackageJson.version}`
                                : '',
                        )
                        .render(),
                )

                return r()

                require('figlet').text(
                    'seXpress',
                    {
                        font: 'Colossal',
                        horizontalLayout: 'default',
                        verticalLayout: 'default',
                    },
                    function (err, data) {
                        if (err) return
                        console.log(data)
                        r()
                    },
                )
            })()
        })
    }

    defaults() {
        return {
            /********** package json *********/
            title: '@title',
            version: '@version',
            defaults: '@defaults',
            description: '@description',
            generate: '@generate',
            name: '@name',
            author: '@author',
            secret: '@secret',
            host: '@host',
            port: '@port',
            subdomains: '@subdomains',

            /********** app defaults *********/
            appPhrase: getQuestion().replace(' i ', ' I '),
            // host: 'localhost',
            protocol: 'http',
            // port: 80,
            run: false,

            /********** module inits *********/
            ssl: { enabled: false },
            folders: {},
            defaults: {},
            // subdomains: {},

            /********** module defaults *********/
            initSeqMessage: 'Sexy Configuration!',
            logging: {
                onlyLogErrors: true,
            },
            /// Note: this starts out empty so that we can assign a default secret in the construction of the config
            authentication: {},
            publicFilter: (c) => c,
            public: {
                meta: true,
                images: true,
                page: true,
            },
        }
    }

    constructor(opts = {}) {
        /// powered by expressjs
        this.app = express()

        /// LOAD CONFIGURATION
        let config = require('clobfig')(this.defaults())

        const utilMiddlewareClass = require('./middleware/util')
        const utilies = new utilMiddlewareClass()
        this.util = utilies
        /// Preset the middlewares.util middleware which is used by the core modules on load,
        /// before the loading of middlewares which is when this will be override by the loading of the util middleware
        this.middlewares = { util: utilies }
        const debugFilename = this.util.getRootPath('config.debug.js')
        const debug = !!config.debug
            ? config.debug
            : process.argv.reduce(
                  (out, arg) =>
                      (out =
                          arg.indexOf('debug=') === 0
                              ? arg.indexOf('debug=true') === 0
                                  ? true
                                  : arg.indexOf('debug=false') === 0
                                  ? false
                                  : arg.substring('debug='.length)
                              : out),
                  false,
              )

        /// Configuration is first initialized here, upon import
        config = this.util.merge(
            config,
            debug
                ? this.util.merge(
                      {
                          host: 'localhost',
                          port: 8080,
                          debug: true,
                      },
                      fs.existsSync(debugFilename) ? require(debugFilename) : {},
                  )
                : {},
        )

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
        // const initPromised = Promise.resolve()

        /// Construct configuration from defaults, config files, and instantiation opts
        this.setConfiguration({
            ...config,
            ...opts,
        })

        process.on('SIGINT', this.stop.bind(this))

        /// TODO: don't allow initialization upon instantiation?
        /// energize
        this._initPromise = [initPromised.then(this.init.bind(this, debug))]
    }

    /// Begin application initialization
    init(debug) {
        return this.util.promiseMe(async (done) => {
            if (!this.config.modules) {
                const modulesFolderFiles = fs.readdirSync(path.join(__dirname, 'modules'))
                const modulesFiles = modulesFolderFiles.filter((f) => f.indexOf('.js') !== -1)

                this.config.modules = modulesFiles.map((m) => m.replace('.js', ''))
            }
            if (!this.config.middlewares) {
                /// TODO: set this somewhere else?
                const defaultEnabledMiddlewares = ['email', 'encrypt', 'util']

                const middlewareFolderFiles = fs.readdirSync(path.join(__dirname, 'middleware'))
                const middlewareFiles = middlewareFolderFiles.filter((f) => f.indexOf('.js') !== -1)
                this.config.middlewares = {}
                middlewareFiles.forEach((middleware) => {
                    const middlewareName = middleware.replace('.js', '')
                    if (middlewareName !== 'index') {
                        this.config.middlewares[middlewareName] =
                            defaultEnabledMiddlewares.indexOf(middlewareName) !== -1
                    }
                })
            }

            /// get the core modules
            this.core = require(path.join(__dirname, 'modules'))(this.config.modules)

            /// Always run the debug module, it sets up the logger, and if it is not present let the errors be thrown
            this.core.debug.bind(this)(debug)

            /// The logger is now ready for use
            this.log.debug(
                `\t\tI promise to ${this.config.run ? 'run' : 'wait'} all ${
                    this.config.run ? 'day' : 'night'
                }.\n\t\t${this.config.appPhrase}\n\n`,
            )
            this.log.status(`\n💃 sexpress -> {${this.config.name}} 💃\n`)
            this.log.debug(`🛰  sexpress core modules definition`, this.core)

            this.log.info(`\t🤖 \x1b[43m\x1b[30m Init \x1b[0m\x1b[0m 🤖`)

            /// Load core modules in this order
            await this.loadModules(this.core, [
                /// precompile
                'generate',

                /// init
                'cache',
                'session',
                'database',
                'logging',

                /// security
                'security',
                'authentication',

                /// dynamic
                'login',
                'config',
                'hooks',
                'api',
                'docs',

                /// runtime
                'robots',
                'rendering',
                'routing',
                'templating',
                'static',
            ])

            /// Add third party middleware support
            this.initMiddlewares(this.config.middlewares)

			await this.loadModules(this.core, [
				/// compile
				'compilation',
				'ssl',

				/// ready
				'errors',
			])

            this.log.debug(`sexpress application {${this.config.name}} initialized`, this.config)

            /// engage?
            if (this.config.run) {
                return this.run().then(done)
            }

            done()
        })
    }

    initMiddlewares(middlewares = {}) {
        this.middlewares = {}
        this.config.middlewares = middlewares || this.config.middlewares
        const middlewaresNames = Object.keys(this.config.middlewares)

        middlewaresNames.forEach((middleware) => {
            if (middleware === 'index') return

            const middlewareNotSupported = class middlewareNotSupported {
                constructor() {
                    return `middleware not supported [${middleware}]`
                }

                init() {}
            }
            const middlewareConfiguredAsBoolean =
                typeof this.config.middlewares[middleware] === 'boolean'
            const middlewareOpts =
                typeof this.config.middlewares[middleware] !== 'undefined'
                    ? middlewareConfiguredAsBoolean
                        ? { enabled: this.config.middlewares[middleware] }
                        : this.config.middlewares[middleware]
                    : { enabled: false }

            const middlewareFileName = path.join(
                this.config.folders.middlewaresFolder,
                `${middleware}.js`,
            )
            const middlewareClass = fs.existsSync(middlewareFileName)
                ? require(middlewareFileName)
                : middlewareNotSupported

            this.middlewares[middleware] = middlewareOpts.enabled
                ? new middlewareClass(middlewareOpts)
                : new middlewareNotSupported()
        })

        middlewaresNames.forEach(async (middleware) => {
            /// TODO: manage middleware state?
            const middlewareInstance = this.middlewares[middleware]
            if (middlewareInstance && middlewareInstance.init) {
                await middlewareInstance.init(this.middlewares)
            }
            /// Middlewares can use the following pattern for awaiting setup:
            /// middlewares.redis.onReady.push((redis) => {
            /// 	// do something with the configured client
            /// 	redis.client()
            /// })
        })
    }

    /**** setter methods *****/
    setLogger(logger, loud = false) {
        this.log = logger

        if (this.config.debug) {
            const logError = this.log.error
            this.log.error = (m, o) =>
                logError(Error().stack.replace(/.*node_modules.*\n/g, ''), { m, o })

            if (typeof this.config.debug === 'string' && this.config.debug !== 'all') {
                const logDebug = this.log.debug
                const debugModule = this.config.debug

                this.log.debug = function (message, obj, debugName) {
                    if (!debugName) {
                        if (typeof obj === 'string') {
                            debugName = message
                            message = obj
                            obj = null
                        } else {
                            debugName = 'core'
                        }
                    } else {
                        const t = message
                        message = obj
                        obj = debugName
                        debugName = t
                    }
                    if (debugName === debugModule) {
                        logDebug(message, obj)
                    }
                }
            }
        }

        if (this.config.silent || !loud) {
            /// Drop the data
            const statusLogWithoutData = this.log.status
            const infoLogWithoutData = this.log.info
            this.log.status = (m) => statusLogWithoutData(m)
            this.log.info = (m) => infoLogWithoutData(m)
        }
    }

    setConfiguration(config) {
        this.config = config
        /// TODO: make the modules register themselves as a core subdomain
        this.coreSubdomains = this.config.coreSubdomains || []

        const setMissingPackageJsonValues = (values = {}) => {
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
                : this.util.getRootPath(rootPath)
        }

        /// Set missing values from the default configuration that could have been loaded from the package json
        setMissingPackageJsonValues({
            /// Generate a random application name if one is not provided
            name: getPersonName(),
            /// Let's randomly generate a secret to be used globally
            secret: `${new Date().getTime()}-${rword.generate(3).join('~')}--${Math.random()}`,
            /// If there is no version set, then this is not a production application
            version: '0.0.0-beta.0',
            /// The default host is localhost
            host: 'localhost',
            /// The default port is 80
            port: 80,
            /// There are no subdomains set, so this should be a simple server
            subdomains: {},
            /// 0 out these fields
            author: null,
            generate: false,
        })

        this.config.folders.staticFolders = this.config.folders.staticFolders || []
        this.config.folders.appFolder = getThisOrDefaultOrRootFolder('appFolder', '', true)
        this.config.folders.publicFolder = getThisOrDefaultOrRootFolder('publicFolder')
        this.config.folders.configFolder = getThisOrDefaultOrRootFolder('configFolder')
        this.config.folders.sslFolder = getThisOrDefaultOrRootFolder('sslFolder', ['config', 'ssl'])
        this.config.folders.srcFolder = getThisOrDefaultOrRootFolder('srcFolder')
        this.config.folders.dockerFolder = getThisOrDefaultOrRootFolder('dockerFolder')
        this.config.folders.templatesFolder = getThisOrDefaultOrRootFolder('templatesFolder')
        this.config.folders.controllersFolder = getThisOrDefaultOrRootFolder('controllersFolder')
        this.config.folders.middlewaresFolder = path.join(__dirname, 'middleware')

        this.config.folders.contentFolder = getThisOrDefaultOrRootFolder(
            'contentFolder',
            path.join('public', 'content'),
            true,
        )
        this.config.folders.viewsFolder = getThisOrDefaultOrRootFolder(
            'viewsFolder',
            path.join('controllers', 'views'),
            true,
        )
        this.config.getRootPath = this.util.getRootPath

        Object.keys(this.config.subdomains).forEach((subdomain) => {
            if (this.coreSubdomains.indexOf(subdomain) !== -1) {
                this.log.info('overriding core subdomain', subdomain)
            }
            const subdomainConfiguration = this.config.subdomains[subdomain]

            const mergedSubdomainConfiguration = this.util.merge(
                this.config.defaults,
                subdomainConfiguration,
            )

            this.authTokens[subdomain] = this.util.getValuesFromObjectOrDefault(
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

        const authorEmail = this.config.author
            ? this.config.author.split(' ')[0]
            : this.config.name.replace(' ', '.')
        this.config.author = {
            name: authorEmail,
            email: this.config.author
                ? this.util.extractEmails(this.config.author)[0]
                : `${authorEmail}@${this.config.host}`,
        }

        this.config.authentication.secret =
            this.config.authentication.secret ||
            this.config.name.replace(' ', '_').toLocaleLowerCase()

        this.config.content = content
    }

    /**** application methods *****/
    registerController(controller, root = '') {
        const applet = express()

        root = controller.root ? controller.root : root
        const controllerName = root ? root : this.config.routing.indexControllerName

        this.log.info(`🪐 registering controller: <${controllerName}>`)
        this._customRoutesAdded = []

        const prefix = `${controller.prefix ? controller.prefix : root}`
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

            const viewFiles = this.util.getViews(this.config, viewsFolder)
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
                `registering hooks: ${this.util.consoleLogEmojiNumber(hooks.length)}`,
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
            const url = `/${prefix}${postfix}`
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
                    `custom routes: ${this.util.consoleLogEmojiNumber(
                        this._customRoutesAdded.length,
                    )}`,
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

    registerCoreSubdomain(subdomain) {
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
        return this.util.promiseMe(async (done) => {
            order = order || Object.keys(modules)

            if (modules) {
                for (let i = 0; i < order.length; ++i) {
                    const module = order[i]
                    const moduleDefaults = modules[module].defaults
                    // const moduleIsEnabled = typeof moduleDefaults === 'boolean' && (moduleDefaults && moduleDefaults.enabled)

                    /// Pass the default paramaeters as the initial state of the module
                    const moduleInitPromise = modules[module].bind(this, moduleDefaults)()

                    if (this.util.isPromise(moduleInitPromise)) {
                        const error = await moduleInitPromise
                        if (error) {
                            // this.log.error(`cannot initialize due to error`, error)
                            throw error
                        }
                    }
                }
            }
            done()
        })
    }

    apiRoute(endpoint, response, methods = 'post') {
        /// Normalize the methods to an array
        methods = typeof methods === 'string' ? [methods] : methods
        /// Normalize the endpoint to drop the /api if passed in
        endpoint = endpoint.indexOf('/api') === 0 ? endpoint.replace('/api', '') : endpoint

        /// Ignore core modules and any subdomains passed in
        const ignoreSubdomains = Object.keys(this.core).filter((m) => ['index'].indexOf(m) === -1)
        const subdomains = Object.keys(this.config.subdomains).filter(
            (s) => ignoreSubdomains.indexOf(s) === -1,
        )
        /// Set the external api endpoint
        const publicApiRoute = `${
            this._customControllerRoutePrefix === 'api'
                ? ''
                : `/${this._customControllerRoutePrefix}`
        }${endpoint}`
        /// Set the internal api endpoint
        const internalApiRoute = `/api${publicApiRoute}`

        /// Add the internal routes
        methods.forEach((method) => {
            /// If the external API method is a get, then there's no auth required and it can access at the root
            if (method.toLocaleLowerCase() === 'get') {
                this.log.debug(`✨  adding public`, publicApiRoute)
                this.app[method](
                    publicApiRoute,
                    /// dont intercept any core module subdomains
                    this.requestHandler(response, subdomains),
                )
            } else {
                this.log.debug(`✨  adding internal`, internalApiRoute)
                this.app[method](
                    internalApiRoute,
                    this.isAuthenticatedHandler(),
                    this.requestHandler(response, subdomains),
                )
            }
        })

        /// TODO: check if the external api is enabled
        /// Add a route for each subdomain on the api.{host} subdomain (api.{host}/{subdomain}/{endpoint})
        subdomains.forEach((subdomain) => {
            const subdomainApiRoute = `${subdomain === 'index' ? '' : `/${subdomain}`}${endpoint}`

            /// Only add the external routes to the internal memory
            this.routes.push(subdomainApiRoute)

            /// Add the external api rouest at api.{host}/{controller}
            methods.forEach((method) => {
                this.log.debug(`✨  adding external`, subdomainApiRoute)
                this.app[method](
                    subdomainApiRoute,
                    this.isAuthenticatedHandler(),
                    this.requestHandler(response, ['api']),
                )
            })
        })
    }

    proxy(endpoint, reroute, proxyOpts = {}) {
        this.app.use(endpoint, reroute, proxyOpts)
    }

    route(endpoint, response, methods = 'get', secure, subdomains) {
        const routeIsApiEndpoint = this._customControllerRoutePrefix === 'api'
        const forceInsecure = typeof secure === 'boolean' ? !secure : false
        const functionName = this.util.getFunctionName(response)

        /// Normalize the methods to an array
        methods = typeof methods === 'string' ? [methods] : methods
        methods.forEach((method) => {
            this._customRoutesAdded.push({ method, endpoint, functionName })

            /// Send the route to the apiRoute method to be given the api module treatment, unless specified to be insecure
            if (routeIsApiEndpoint && !forceInsecure) {
                this.apiRoute(endpoint, response, method)
            } else {
                /// Set the endpoint path with the controller name as a prefix (when registering controllers on initialization)
                endpoint = `${
                    endpoint.indexOf(this._customControllerRoutePrefix) === -1
                        ? this._customControllerRoutePrefix
                            ? `/${this._customControllerRoutePrefix}`
                            : ''
                        : ''
                }${endpoint}`

                if (secure) {
                    this.app[method](
                        endpoint,
                        this.requestHandler(undefined, subdomains),
                        this.isAuthenticatedHandler(response),
                        // this.requestHandler(this.isAuthenticatedHandler(response), subdomains),
                    )
                } else {
                    this.app[method](endpoint, this.requestHandler(response, subdomains))
                }
            }

            if (!this._customControllerRoutePrefix || !this._customControllerRoutePrefix.length) {
                this.log.debug(`✨  <${method}> -> ${endpoint}${secure ? ' *' : ''}`, [
                    functionName,
                ])
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
        return (req, res) => {
            // this.log.debug('viewHandler')
            const { host, subdomain } = res.locals
            const params = typeof req.params === 'object' ? req.params : {}
            const data = this.getPublicData(subdomain, host, params, res)

            // this.log.debug('rendering view', {
            // 	data,
            // 	view,
            // 	locals: res.locals,
            // })
            return res.render(view, data)
        }
    }

    templateHandler(template) {
        return (req, res, next) => {
            // this.log.debug('templateHandler')
            const subdomain = res.locals.subdomain
            const host = res.locals.host

            if (!subdomain) {
                this.log.error('Subdomain not set for use with template, falling through', {
                    subdomain,
                    hostNotFound: host,
                })

                return next()
            }

            const params = typeof req.params === 'object' ? req.params : {}
            const data = this.getPublicData(subdomain, host, params, res)

            return this.renderTemplate(template, data, res)
        }
    }

    requestHandler(handler, restrictedSubdomains = [], skipLogging = false) {
        return (req, res, next) => {
            const subdomain = res.locals.subdomain
            const handlerName = this.util.getFunctionName(handler)
            this.log.debug('requestHandler', { subdomain, handlerName })

            if (
                restrictedSubdomains.length &&
                !this.isValidSubdomain(subdomain, restrictedSubdomains, this.coreSubdomains)
            ) {
                if (
                    !this.config.templating.headless ||
                    subdomain === this.config.routing.indexControllerName
                ) {
                    return next()
                }

                this.log.error(`🛑 request invalid for subdomain [${subdomain}]`, {
                    handler,
                    handlerName,
                    subdomain,
                    restrictedSubdomains,
                    url: req.url,
                    host: req.hostname,
                    subdomains: req.subdomains,
                })
                return res.redirect(this.getBaseUrl())
            }

            const url = req.url
            skipLogging =
                skipLogging || new RegExp(this.config.logging.ignoreRoutes.join('|')).test(url)

            if (!skipLogging || this.config.debug) {
                const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress
                const reqIsOptionOrGet =
                    ['options', 'get'].indexOf(req.method.toLocaleLowerCase()) !== -1
                const handlerDisplayName = handler
                    ? handler.name
                        ? handler.name
                        : handlerName || '*()'
                    : 'passthrough'
                this.log.status(
                    ` ${reqIsOptionOrGet ? `👆` : `👇`} [${
                        req.method
                    }] ${handlerDisplayName}:${ip} (${subdomain} > ${url})`,
                    {
                        handler: handlerDisplayName,
                        url,
                        subdomain,
                        ip,
                        body: !reqIsOptionOrGet ? req.body : undefined,
                    },
                )
            }

            if (handler && typeof handler === 'function') {
                return handler.call({ app: this }, req, res, next)
            }

            return next()
        }
    }

    /**** getter methods *****/
    /// Only returns the keyvals stored in the app
    get(name = '') {
        this.app.get(name)
    }

    getApis() {
        const excludeTheseControllers = this.util.merge(
            Object.keys(this.core).filter((f) => f !== 'api'),
            this.config.privateApis || [],
        )
        const controllers = this.util.getControllers(
            this.config,
            this.config.folders.controllersFolder,
            excludeTheseControllers,
        )

        return controllers
    }

    getAvilableSSOProviders(subdomain) {
        const ssoProviders = []

        Object.keys(this.config.authentication).forEach((authenticationName) => {
            const subdomainAuthOpts =
                subdomain !== 'index' && this.authTokens[subdomain]
                    ? this.authTokens[subdomain]
                    : this.authTokens.default
            if (
                subdomainAuthOpts[authenticationName] &&
                subdomainAuthOpts[authenticationName].clientID
            ) {
                ssoProviders.push(authenticationName)
            }
        })

        return ssoProviders
    }

    getBaseUrl(host, protocol, subdomain, fullHost) {
        return this.util.getHostBaseUrl(this.config, host, protocol, subdomain, fullHost)
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
        defaults.enabled =
            typeof defaults.enabled !== 'undefined'
                ? defaults.enabled
                : typeof initial === 'undefined'
                ? true
                : !!initial

        const fromConfig =
            typeof this.config[moduleName] === 'boolean'
                ? { enabled: this.config[moduleName] }
                : typeof this.config[moduleName] === 'undefined'
                ? {}
                : this.config[moduleName]
        const moduleOpts = this.util.merge.all([defaults, fromConfig, overrides])
        this.log.debug(`initialized core module options for [${moduleName}]`, moduleOpts)

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

    getPort() {
        const appPort = this.app.get('port')

        return appPort || this.config.port
    }

    getLoginUrl(req = {}, subdomain, ignoreSubdomains = []) {
        subdomain = subdomain && ignoreSubdomains.indexOf(subdomain) !== -1 ? '' : subdomain

        let loginHost = req.hostname
        const loginPath = subdomain !== 'login' ? '/login' : ''
        const protocol = req.protocol || this.config.protocol
        const port = this.getPort() !== 80 ? `:${this.getPort()}` : ''

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

    getPublicData(subdomain, host, overrides = {}, res, uncached = false) {
        const cacheKey = `getPublicData::${subdomain}.${host}`
        let getPublicDataResponse = this.cache.get(cacheKey)

        if (!getPublicDataResponse || uncached) {
            const loginUrl = this.getLoginUrl({ hostname: host }, subdomain, Object.keys(this.core))
            const publicConfig = {
                loginUrl,
                host,
                origin: this.getBaseUrl(true),
                SUBDOMAIN: subdomain.toUpperCase(),
                thisSubdomain: subdomain,
                debug: this.config.debug,
                content: this.config.content,
                subdomains: [],
                api:
                    this.config.compilation && this.config.compilation.enabled
                        ? this.config.compilation.opts &&
                          this.config.compilation.opts.output.filename
                        : this.config.api.apiFilename,
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
                    const merged = this.util.getValuesFromObjectOrDefault(
                        fields,
                        subdomainInformation,
                        overrides,
                        defaults,
                    )

                    pageData[fieldName] = merged[fieldName]
                })

                pageData.hasCustomCss = fs.existsSync(customCssPath)

                if (subdomain === subdomainName) {
                    publicConfig.page = this.util.merge(pageData, overrides)
                }

                publicConfig.subdomains[subdomainName] = pageData
            })

            publicConfig.content = this.config.content

            if (uncached) this.cache.set(cacheKey, publicConfig)
            getPublicDataResponse = publicConfig
        }

        getPublicDataResponse = this.util.merge(getPublicDataResponse, {
            nonce: res.locals.nonce,
        })

        return this.config.publicFilter(getPublicDataResponse, this.config, subdomain)
    }

    async getRedisValues(keys, callback) {
        if (this.middlewares.redis && this.middlewares.redis.server) {
            const redisClient = this.middlewares.redis.client()
            if (!callback) {
                let redisValues = []
                callback = (err, response) => {
                    if (err) {
                        this.log.error(`error getting redis keys`, { error: err, keys })
                        return
                    }

                    redisValues = response
                }
                redisClient.mget(keys, callback)

                console.log({ redisValues, keys })

                return redisValues
            }

            return redisClient.mget(keys, callback)
        }

        return null
    }

    async setRedisValue(key, value) {
        if (this.middlewares.redis && this.middlewares.redis.server) {
            const redisClient = this.middlewares.redis.client()
            // console.log({redisClient, keys})
            const redisSetPromse = redisClient.setAsync(key, value, require('redis').print)
            console.log({ redisSetPromse })
            return redisSetPromse
        }

        return undefined
    }

    async getRedisKeys(keys = '*', callback, returnValues = true) {
        if (this.middlewares.redis && this.middlewares.redis.server) {
            const redisClient = this.middlewares.redis.client()
            // console.log({redisClient, keys})

            if (!callback) {
                const redisKeys = []
                callback = (err, response) => {
                    if (err) {
                        this.log.error(`error getting redis keys`, { error: err, keys })
                        return
                    }

                    redisKeys = response
                }
                console.log({ redisKeys, keys })

                if (!redisKeys.length) return {}

                await redisClient.multi().keys(redisKeys, callback)

                if (!returnValues) return redisKeys

                let keyValues = {}

                redisClient.mget(redisKeys, (e, keyVals) => {
                    if (err) {
                        this.log.error(`error getting redis keys values`, {
                            error: e,
                            keys,
                            redisKeys,
                        })
                        return
                    }
                    console.log({ keyVals })

                    keyValues = keyVals
                })

                return keyValues
            }

            if (returnValues) {
                const cb = callback
                callback = (err, keys) => {
                    if (err) {
                        this.log.error(`error getting redis keys`, { error: err })
                        return
                    }

                    return redisClient.mget(keys, cb)
                }
            }

            return redisClient.multi().keys(keys, callback)
        }

        return {}
    }

    getRequestOrigin(req) {
        const host = this.config.host
        const subdomain = this.util.getSubdomainPrefix(this.config, req)
        const subdomainPrefix = `${
            subdomain == this.config.routing.indexControllerName ? '' : `${subdomain}.`
        }`
        const protocol = req.protocol
        const reconstructedUrl = `${protocol}://${subdomainPrefix}${host}`

        return reconstructedUrl
    }

    getSubdomainOpts(req, uncached) {
        const isString = (typeof req).toLocaleLowerCase() === 'string'
        const subdomain = isString ? req : this.util.getSubdomainPrefix(this.config, req)
        const cacheKey = `getSubdomainOpts::${subdomain}`
        let getSubdomainOptsResponse = this.cache.get(cacheKey)

        if (!getSubdomainOptsResponse || uncached) {
            if (!!this.config.subdomains[subdomain]) {
                getSubdomainOptsResponse = this.config.subdomains[subdomain]
            } else {
                const subdomainAliased = Object.values(this.config.subdomains).filter((sub) => {
                    return sub.aliases && sub.aliases.indexOf(subdomain) !== -1
                })
                getSubdomainOptsResponse = subdomainAliased.length ? subdomainAliased[0] : {}
            }

            if (!uncached) this.cache.set(cacheKey, getSubdomainOptsResponse)
        }

        return {
            requestSubdomain: subdomain,
            requestHost: req.hostname,
            ...getSubdomainOptsResponse,
        }
    }

    getSubdomainFromAlias(alias) {
        return this.util.getSubdomainFromAlias(this.config, alias)
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

    getSwaggerSpec(opts, overrides = {}, uncached = false) {
        const cacheKey = `getSwaggerSpec::()`
        let getSwaggerSpecResponse = this.cache.get(cacheKey)

        if (!getSwaggerSpecResponse || uncached) {
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
                    url: this.util.getHostUri(
                        opts,
                        opts.host,
                        undefined,
                        opts.api.docsEndpoint,
                        true,
                    ),
                },
                servers: overrides.servers
                    ? []
                    : [
                          {
                              url: `http://${overrides.host || opts.host}`,
                          },
                      ],
            }

            const openApiDefinition = this.util.merge(
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
                    openApiDefinition.authentication = this.util.merge(
                        Object.keys(securitySchemes).reduce((o, s) => {
                            o[s] = []
                            return o
                        }, {}),
                    )
                }

                openApiDefinition.components = { securitySchemes, responses, schema, requestBodies }
            }

            const swaggerDefinition = this.util.merge(openApiDefinition, overrides)

            const jsDocOpts = {
                swaggerDefinition,
                apis: this.getApis(),
            }

            getSwaggerSpecResponse = swaggerJSDoc(jsDocOpts)
            if (!uncached) this.cache.set(cacheKey, getSwaggerSpecResponse)
        }

        return getSwaggerSpecResponse
    }

    getTemplateNameFromSubdomain(subdomain) {
        if (!!this.config.subdomains[subdomain]) {
            return this.config.subdomains[subdomain].template
        }

        return null
    }

    getUserData(req, subdomain, host) {
        const userData = {
            user: req.user,
            host: host || this.getHost(req),
            origin: this.getHost(),
            name: this.config.name,
            appPhrase: this.config.appPhrase,
            loginUrl: this.getLoginUrl(req, subdomain),
            sso: this.getAvilableSSOProviders(subdomain),
        }

        return userData
    }

    /**** validator methods *****/
    isAuthenticatedHandler(finale) {
        return (req, res, next) => {
            if (!this.isAuthenticated(req)) {
                const { subdomain } = res.locals
                const activeAuthStrategies = this.config.authentication.schemes
                    ? this.config.authentication.schemes.map((s) => s.name || s)
                    : []

                if (activeAuthStrategies.length) {
                    /// Try all of the authentication methods
                    return this.authenticate(activeAuthStrategies, subdomain, (err, user) => {
                        if (!err && user) return next()

                        this.log.debug('exhausted authenticators', {
                            url: req.url,
                            user,
                            auth: req.headers.authorization,
                        })

                        if (req.method === 'GET') {
                            finale = typeof finale === 'string' ? finale : this.getLoginUrl(req)
                            return res.redirect(finale)
                        } else {
                            return res.status(401).end()
                        }
                    })(req, res, next)
                } else {
                    this.log.error(
                        `authentication required for route but no authentication schemes are configured`,
                        this.config.authentication,
                    )
                }
            }

            if (typeof finale === 'function') {
                return finale.call({ app: this }, req, res, next)
            }
            next()
        }
    }

    getCookies(req = {}) {
        const reqCookie = req.cookie
        const reqCookies = req.cookies
        const sessionCookie = req.session ? req.session.cookies : undefined
        const signedSessionCookie = req.session ? req.session.signedCookies : undefined
        const headerCookie = req.header.cookie
        const headerCookies = req.header.cookies

        // console.log({
        //     reqCookie,
        //     reqCookies,
        //     sessionCookie,
        //     signedSessionCookie,
        //     headerCookie,
        //     headerCookies,
        // })

        if (req.cookies) return req.cookies

        /// Check for session cookies
        if (req.session) {
            // console.log({ passport: req.session.passport })
            const cookiesSet = req.cookies || req.session.cookies || req.session.signedCookies

            if (!cookiesSet) return cookiesSet
        }

        return []
    }

    isAuthenticated(req = {}) {
        const requestIsAuthenticated = req.isAuthenticated && req.isAuthenticated()

        /// Is this a valid cookie? Do we even need to check?
        if (!requestIsAuthenticated && req.passport) {
            if (req.passport && req.passport.user) return true
        } else {
            const cookiesSet = this.getCookies(req)
            // console.log({
            //     requestIsAuthenticated,
            //     cookiesSet,
            //     passport: req.passport,
            // })
            // console.trace()
            // if (cookiesSet.length) return false
        }

        return requestIsAuthenticated
    }

    isRunning() {
        return this._running
    }

    isValidRequestOrigin(req, origin, subdomain) {
        /// All requests should match this host
        const host = this.config.host
        origin = origin ? origin : req.get('origin') || 'none'
        subdomain = subdomain ? subdomain : this.util.getSubdomainPrefix(this.config, req)

        const subdomainPrefix = `${
            subdomain == this.config.routing.indexControllerName ? '' : `${subdomain}.`
        }`
        const protocol = req.protocol

        const getReconstructedUrl = (subdomainPrefix) => `${protocol}://${subdomainPrefix}${host}`
        const checkSubdomainAgainstOrigin = (subdomainPrefix) => {
            return origin == getReconstructedUrl(subdomainPrefix)
        }
        const checkAliasesAgainstOrigin = () => {
            let index = 0,
                valid = false
            const aliases = !this.config.subdomains[subdomain]
                ? []
                : this.config.subdomains[subdomain].aliases || []
            while (aliases[index] && (valid = checkSubdomainAgainstOrigin(`${aliases[index++]}.`)))
                return valid
        }

        const reconstructedUrl = getReconstructedUrl(subdomainPrefix)
        const localhostPortIsTheSameForDebugging =
            origin === reconstructedUrl || origin === `${reconstructedUrl}:${this.getPort()}`
        const originIsCorrectSubdomain = checkSubdomainAgainstOrigin(subdomainPrefix)
        const originIsCorrectAliasedSubdomain = originIsCorrectSubdomain
            ? true
            : checkAliasesAgainstOrigin()
        const originIsValid =
            originIsCorrectSubdomain ||
            originIsCorrectAliasedSubdomain ||
            localhostPortIsTheSameForDebugging

        /// TODO: fix bug here
        if (originIsValid) {
            this.log.debug(`✅  origin ${origin} is valid`)
        } else {
            this.log.debug(`❗️  origin ${origin} is not valid`, {
                localhostPortIsTheSameForDebugging,
                originIsCorrectAliasedSubdomain,
                originIsCorrectSubdomain,
                reconstructedUrl,
                originIsValid,
                subdomain,
                origin,
            })
        }

        return originIsValid
    }

    isValidSubdomain(subdomain, validSubdomains = [], ignoreSubdomains = []) {
        if (!validSubdomains.length) return true

        const configuredSubdomains = Object.keys(this.config.subdomains)
        const isConfiguredSubdomain = configuredSubdomains.indexOf(subdomain) !== -1
        const subdomainIsConfiguredCoreModule =
            isConfiguredSubdomain && this.coreSubdomains.indexOf(subdomain) !== -1
        const isNotRestricted =
            validSubdomains.indexOf(subdomain) !== -1 || subdomainIsConfiguredCoreModule

        if (!isNotRestricted)
            this.log.debug({
                subdomain,
                validSubdomains,
                configuredSubdomains,
                subdomainIsConfiguredCoreModule,
            })

        return isNotRestricted
    }

    /**** runtime methods *****/
    /// Runs the express (wr)app with all of the middleware configured
    run() {
        /// We promised we would initialize first
        return Promise.all(this._initPromise).then(
            async function RunSexpress() {
                this.log.debug(`I fullfilled all of my promises, now. ${this.config.appPhrase}`)

                // const debuggingLocalhost = this.config.debug && this.config.host === 'localhost'

                let httpsServer = null,
                    serverOpts = {},
                    httpServer = http.createServer(serverOpts, this.app)

                const errorHandler = (error, message) => {
                    message = `❗️  Encountered fatal error [${error.code}]${
                        message ? ` - ${message}` : ''
                    }: `
                    switch (error.code) {
                        case 'EADDRINUSE':
                            message = `${message} is there another server running on this port?`
                        default:
                            this.log.error(`server start error ${error.code}`, message)
                    }

                    this._running = false
                }

                /// Load runtime modules
                if (this.config.ssl.enabled) {
                    httpsServer = await this.__ssl(serverOpts)
                    const httpsServerPort = this.config.ssl.port
                    if (httpsServer) {
                        httpsServer
                            .listen(httpsServerPort, () => {
                                this.log.status(
                                    `\n💃 *{${this.config.name}}* @ https://${this.config.host}${
                                        httpsServerPort !== 443 || httpsServerPort !== 8443
                                            ? `:${httpsServerPort}`
                                            : ''
                                    } 💃 \n\n`,
                                )
                            })
                            .on('error', (e) => errorHandler(e, 'FATAL ❗️ HTTPS server error'))
                    }

                    if (httpsServerPort !== 80 || !httpsServer) {
                        httpServer = null
                        this.app.set('port', httpsServerPort)
                        this.config.port = httpsServerPort
                    }
                }

                if (httpServer) {
                    const httpServerPort = this.getPort()
                    httpServer
                        .listen(httpServerPort, () => {
                            this.log.status(
                                `\n💃 {${this.config.name}} @ http://${this.config.host}${
                                    httpServerPort !== 80 ? `:${httpServerPort}` : ''
                                } 💃 \n\n`,
                            )
                        })
                        .on('error', (e) => errorHandler(e, 'FATAL ❗️ HTTP server error'))
                    this.app.set('port', httpServerPort)
                    this.config.port = httpServerPort
                }

                if (this.config.debug) {
                    this.__debug()
                }

                this._running = true
                this.log.info(`\t🤖 \x1b[42m\x1b[30m Ready \x1b[0m\x1b[0m 🤖`)
            }.bind(this),
        )
    }

    async stop() {
        /// Cleanup?
        /// Save state?

        /// TODO: have this be called from a hook
        Object.keys(this.middlewares).forEach(async (middleware) => {
            if (this.middlewares[middleware].close) {
                await this.middlewares[middleware].close()
            }
        })

        if (this.config.preserve) {
            const preservedConfig = {}
            /// config.js files are loaded after config.json files, so zzz should always come last?
            const preservedConfigFilePath = join(
                this.config.folders.configFolder,
                `zzz.config.json`,
            )
            const preserveOptions =
                typeof this.config.preserve === 'array' ? this.config.preserve : ['authentication']

            /// TODO: save the config values that are present in the list
            preserveOptions.forEach((opt) => {
                preservedConfig[opt] = this.config[opt]
            })

            fs.writeFileSync(preservedConfigFilePath, JSON.stringify(preservedConfig))
        }

        this.log.info(`\t🤖 \x1b[41m\x1b[37m Stopped \x1b[0m\x1b[0m 🤖`)
        process.exit()
    }

    authenticate(strategies, subdomain, opts) {
        strategies = typeof strategies === 'string' ? [strategies] : strategies

        /// TODO: change this, as it just returns the first strategy it can find
        if (this.authTokens[subdomain] && this.authTokens[subdomain][strategies]) {
            if (opts)
                return this.authTokens[subdomain][strategies].passport.authenticate(
                    strategies,
                    opts,
                )

            return this.authTokens[subdomain][strategies].passport.authenticate(strategies)
        } else if (this.authTokens.default && this.authTokens.default[strategies]) {
            if (opts)
                return this.authTokens.default[strategies].passport.authenticate(strategies, opts)

            return this.authTokens.default[strategies].passport.authenticate(strategies)
        }

        return () => {}
    }

    renderSync(view, options) {
        // this.log.debug('renderSync')

        /// Ensure the views path is set
        const viewFilePath = path.join(
            this.app.get('views'),
            view.replace(this.app.get('views'), ''),
        )
        let rendered

        // this.log.debug('rendering view', { view })
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

        // this.log.debug('rendering view', {
        // 	view,
        // 	viewFilePath,
        // })
        return this.__renderer(viewFilePath, options, callback)
    }

    renderTemplateOrView(template, data, res) {
        // this.log.debug('renderTemplateOrView')
        const findTemplateFile = (engine) => {
            const templateFile = path.join(
                this.config.folders.templatesFolder,
                `${template}.${engine}`,
            )
            if (fs.existsSync(templateFile)) return templateFile

            const templateFileIndex = path.join(
                this.config.folders.viewsFolder,
                `${template}/index.${engine}`,
            )
            if (fs.existsSync(templateFileIndex)) return templateFileIndex

            return false
        }

        let foundTemplate = false
        if (
            (typeof engine === 'undefined' &&
                typeof this.config.rendering.overrideViewEngine === 'array') ||
            typeof this.config.rendering.overrideViewEngine === 'object'
        ) {
            for (const engine of this.config.rendering.overrideViewEngine) {
                if ((foundTemplate = findTemplateFile(engine))) break
            }
        } else {
            foundTemplate = findTemplateFile(this.config.rendering.overrideViewEngine)
        }

        if (foundTemplate) {
            return this.renderTemplate(foundTemplate, data, res)
        }

        const viewFilePath = this.util.findViewFile(this.config, template)
        return res.render(viewFilePath, data)
    }

    renderViewOrTemplate(view, data, res) {
        // this.log.debug('renderViewOrTemplate')
        const foundView = this.util.findViewFile(this.config, view)

        if (foundView) {
            // this.log.debug('rendering view', {
            // 	data,
            // 	foundView,
            // 	locals: res.locals,
            // })

            return res.render(foundView, data)
        }

        return this.renderTemplate(view.replace('/index', ''), data, res)
    }

    renderTemplate(template, data, res, engine) {
        // this.log.debug('renderTemplate')
        engine = engine ? engine : this.config.rendering.overrideViewEngine

        if (!template) {
            if (!this.config.routing.indexControllerName) {
                this.log.error('cannot render template', { template, engine })
                return res.redirect(this.getBaseUrl())
            }

            /// TODO: add the line below as a final fallback
            // template = this.config.routing.indexControllerName
            template = res.locals.subdomain
            this.log.status('no template set for domain, providing index', { template, engine })
        }

        const fullPathIsInTemplateName =
            template.indexOf(this.config.folders.templatesFolder) !== -1

        if (typeof engine === 'array' || typeof engine === 'object') {
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
                this.log.error(`could not render template ${template}`, { engine })
                return res.status(409).end()
            }

            return success
        }

        template = template.replace(`.${engine}`, '')
        const pageTemplate = fullPathIsInTemplateName
            ? template
            : path.join(this.config.folders.templatesFolder, template)
        const pageTemplateIndex = path.join(pageTemplate, 'index')
        const viewTemplate = `${pageTemplate}.${engine}`
        const viewTemplateIndex = `${pageTemplateIndex}.${engine}`
        const htmlFallbackTemplate = `${pageTemplate}.html`
        const htmlFallbackTemplateIndex = `${pageTemplateIndex}.html`

        this.log.debug(`Searching for template [${template}]`, {
            pageTemplate,
            viewTemplate,
            htmlFallbackTemplate,
            pageTemplateIndex,
            viewTemplateIndex,
            htmlFallbackTemplateIndex,
        })
        if (this.config.rendering.enabled) {
            const viewTemplateFound = fs.existsSync(viewTemplate)
                ? viewTemplate
                : fs.existsSync(viewTemplateIndex)
                ? viewTemplateIndex
                : null

            if (viewTemplateFound) {
                res.locals.partials = path.join(this.config.folders.controllersFolder, 'views', '/')

                this.log.debug('rendering template', {
                    viewTemplateFound,
                    locals: res.locals,
                })

                res.render(viewTemplateFound, data)
                return true
            }
        }

        const htmlFallbackTemplateFound = fs.existsSync(htmlFallbackTemplate)
            ? htmlFallbackTemplate
            : fs.existsSync(htmlFallbackTemplateIndex)
            ? htmlFallbackTemplateIndex
            : null
        if (htmlFallbackTemplateFound) {
            this.log.debug('serving html file', htmlFallbackTemplateFound)
            res.sendFile(htmlFallbackTemplateFound)
            return true

            /// TODO: Send data somehow?
        }

        return false
    }

    /**** middleware access methods *****/
    /// TODO: make middleware methods configurable
    sendEmail(subdomainConfig, opts = {}) {
        if (!this.middlewares.email) return undefined

        const subdomainConfigWithAuth = !!subdomainConfig ? subdomainConfig : this.config

        if (subdomainConfig && opts.useOauth) {
            subdomainConfigWithAuth.authTokens = this.authTokens[subdomainConfig.requestSubdomain]
        }

        return this.middlewares.email.sendEmail(
            subdomainConfigWithAuth,
            opts.to,
            opts.subject,
            opts.text,
            opts.callback,
            opts.html,
            opts.from,
        )
    }

    crypto(secret = null) {
        if (!this.middlewares.encrypt) return undefined

        return {
            algo: this.middlewares.encrypt.md5,
            decrypt: this.middlewares.encrypt.decrypt.bind(
                this.middlewares.encrypt,
                secret || this.config.secret,
            ),
            encrypt: this.middlewares.encrypt.encrypt.bind(
                this.middlewares.encrypt,
                secret || this.config.secret,
            ),
        }
    }

    /**** private methods *****/
    /// Protects connections to the server with an ssl certificate
    __ssl() {
        /// TODO: nothing, I guess?
    }
    /// The default renderer
    __renderer() {
        /// TODO: this should probably return something
        this.log.error(`default renderer is not set!`)
    }

    /// Adds development server debugging functionality
    __debug() {
        const watchPath = this.util.getRootPath('templates')
        if (fs.existsSync(watchPath)) {
            const self = this
            const reloadServer = reload(self.app, {
                https: this.config.ssl.enabled ? this.config.ssl.opts : undefined,
            })
            reloadServer.then(function (reloadReturned) {
                watch.watchTree(watchPath, (f, curr, prev) => {
                    /// TODO: reset page cache for all paths that match the changed filepath
                    /// TODO: to support the above, change the cacheKeys in rendering.js to drop the filename extension
                    self.log('Asset change detected, reloading connection')
                    reloadReturned.reload()
                })
            })
        } else {
            this.log.error('cannot watch because folder does not exist', {
                watchPath,
            })
        }
    }
}

module.exports = Sexpress
