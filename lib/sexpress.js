const express = require('express')
const session = require('express-session')
const path = require('path')
const fs = require('fs')
const bodyParser = require('body-parser')
const nodemailer = require('nodemailer')
const favicon = require('serve-favicon')
const crypto = require('crypto')
const passport = require('passport')
const refresh = require('passport-oauth2-refresh')
const watch = require('watch')
const http = require('http')
const https = require('https')
const reload = require('reload')
const httpErrorPages = require('http-error-pages')
const nodeCache = require('node-cache')
let config = require('clobfig')()

const { getRootPath, log, logger, merge, getValuesFromObjectOrDefault, mkdirp } = require('./util')(
    config.AppRoot,
)

const packageJsonPath = getRootPath('package.json')
const { setInterval } = require('safe-timers')
const { Strategy: ImgurStrategy } = require('passport-imgur')
const { Strategy: RedditStrategy } = require('passport-reddit')
const { version, title: appName, description } = fs.existsSync(packageJsonPath)
    ? require(packageJsonPath)
    : {
          version: 'null',
          appName: null,
          description: null,
      }

const debugFilename = getRootPath('config.debug.js')

const subdomains = !!config.subdomains ? Object.keys(config.subdomains) : []
const authTokens = {}

// Never let debug mode run in production
let debug = !!config.debug
    ? config.debug
    : process.argv.reduce((out, arg) => (out = out || arg.indexOf('--debug=true') !== -1), false)
debug = config.debug = process.env.NODE_ENV !== 'production' ? debug : false

if (debug && fs.existsSync(debugFilename)) {
    config = merge(
        config,
        merge(require(debugFilename), {
            host: 'localhost',
            port: 8080,
            sslport: 8443,
            version,
        }),
    )
}

/// TODO: refactor this method to not run on every request, this is a good candidate for implementing the app cache
const _getPublicConfigurationValues = (opts, subdomain, host, overrides) => {
    const publicConfig = {
        host,
        SUBDOMAIN: subdomain.toUpperCase(),
        thisSubdomain: subdomain,
        debug: opts.debug,
        content: opts.content,
        subdomains: [],
    }

    Object.keys(opts.subdomains).forEach((subdomainName) => {
        const subdomainInformation = opts.subdomains[subdomainName]
        const customCssPath = path.join(__dirname, 'assets/css', `${subdomain}.css`)
        const pageData = getValuesFromObjectOrDefault(
            opts.publicConfigFields,
            subdomainInformation,
            opts,
        )

        pageData.hasCustomCss = fs.existsSync(customCssPath)

        if (subdomain === subdomainName) {
            publicConfig.page = getValuesFromObjectOrDefault(
                undefined,
                pageData,
                overrides,
                undefined,
                true,
            )
        }

        publicConfig.subdomains[subdomainName] = pageData
    })

    publicConfig.content = opts.content

    return opts.publicConfigFilter(publicConfig, opts, subdomain)
}

const _getSubdomainPrefix = (opts, req, returnAlias = false) => {
    const defaultSubdomain = req.subdomains.length ? req.subdomains[0] : 'default'
    const localhostSubdomainEnd = !!req.headers.host ? req.headers.host.indexOf('.') : -1
    const localhostOverride =
        localhostSubdomainEnd !== -1 ? req.headers.host.substr(0, localhostSubdomainEnd) : null
    const alias = !!localhostOverride ? localhostOverride : defaultSubdomain

    return returnAlias ? alias : _getSubdomainFromAlias(opts, alias)
}

const _getSubdomainOpts = (opts, subdomain) => {
    let subdomainConfig = {}

    if (!!opts.subdomains[subdomain]) {
        subdomainConfig = opts.subdomains[subdomain]
    } else {
        const subdomainAliased = Object.values(opts.subdomains).filter((sub) => {
            return sub.aliases.indexOf(subdomain) !== -1
        })
        subdomainConfig = subdomainAliased.length ? subdomainAliased[0] : {}
    }

    return {
        requestSubdomain: subdomain,
        ...subdomainConfig,
        requestHost: opts.hostname,
    }
}

const _getSubdomainFromAlias = (opts, alias) => {
    let baseSubdomain

    Object.keys(opts.subdomains).forEach((baseName) => {
        const aliases = opts.subdomains[baseName].aliases || []
        if (alias === baseName || aliases.indexOf(alias) !== -1) {
            baseSubdomain = baseName
            return
        }
    })

    return baseSubdomain
}

const _getControllers = (opts, controllersFolder) => {
    controllersFolder = controllersFolder ? controllersFolder : opts.controllersFolder
    const indexjs = 'index.js'
    const out = []

    const getControllers = (folder, importAll) => {
        /// Run index.js in this folder first before anything else
        const controllers = fs.readdirSync(folder)
        controllers.sort((a, b) => (a === indexjs ? 1 : b === indexjs ? -1 : 0))

        controllers.forEach((filename) => {
            const file = path.join(folder, filename)

            /// Import all folders under this folder
            if (fs.statSync(file).isDirectory()) {
                if (importAll) getControllers(path.join(folder, filename))

                return
            }

            /// Import only index.js files
            if (filename.indexOf(indexjs) === -1) return
            out.push(path.join(folder, filename))
        })
    }

    if (fs.existsSync(controllersFolder)) {
        getControllers(controllersFolder, true)
    }

    return out
}

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

    // console.log(`Message sent: ${info.messageId}`)

    return callback(info)
}

const _defaults = {
    host: 'localhost',
    run: false,
    initSeqMessage: 'Sexy Configuration!',
    publicConfigFilter: (c) => c,
    publicConfigFields: [],
    version,
    description,
    appName,
}

class Sexpress {
    constructor(opts = {}) {
        /// powered by expressjs
        this.app = express()

        this._customRoutesAdded = []
        this._customControllerRoutePrefix = ''

        /// Construct configuration from defaults, config files, and instantiation opts
        this.setConfiguration({
            ..._defaults,
            ...config,
            ...opts,
        })

        /// Set up the logger
        this.setLogger(log.setDebugging(this.config.debug))

        /// TODO: Allow this process to be configurable
        this.init()
        this.cache()
        this.logging()
        this.security()
        this.routers()
        this.templating()
        this.docs()
        this.authentication()
        this.errors()

        if (this.config.run) {
            this.run()
        }
    }

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
        this.config.appFolder = this.config.appFolder ? this.config.appFolder : getRootPath('')
        this.config.publicFolder = this.config.publicFolder
            ? this.config.publicFolder
            : getRootPath('public')
        this.config.contentFolder = this.config.contentFolder
            ? this.config.contentFolder
            : getRootPath(['public', 'content'])
        this.config.sslFolder = this.config.sslFolder
            ? this.config.sslFolder
            : getRootPath(['config', 'ssl'])
        this.config.templatesFolder = this.config.templatesFolder
            ? this.config.templatesFolder
            : getRootPath('templates')
        this.config.controllersFolder = this.config.controllersFolder
            ? this.config.controllersFolder
            : getRootPath('controllers')
        this.config.viewsFolder = this.config.viewsFolder
            ? this.config.viewsFolder
            : getRootPath('views')
        this.config.getRootPath = getRootPath

        subdomains.forEach((subdomain) => {
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
                subdomainConfiguration[field] = getValuesFromObjectOrDefault(
                    fields,
                    subdomainConfiguration[field],
                    this.config.defaults,
                    this.config,
                )
            })

            authTokens[subdomain] = subdomainConfiguration
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

    addController(controller, name = '') {
        name = controller.name ? controller.name : name

        const controllerName = name ? name : 'default'
        const prefix = `/${controller.prefix ? controller.prefix : name}`
        const applet = express()
        const veiwsFolder = path.join(this.config.controllersFolder, name, 'views')
        const viewGeneratedRoutes = []
        this.log.info(`adding controller: ${controllerName}`)

        if (!name) {
            controller.useRootPath =
                typeof controller.useRootPath !== 'undefined' ? controller.useRootPath : true
        }

        if (typeof controller.init === 'function') {
            this.log.info(`[${controllerName}] -> init`)
            controller.init(this)
        }

        let handler,
            method,
            postfix = '',
            pathMessage,
            atLeastOneGeneratedRoute

        // allow specifying the view engine
        if (controller.engine) {
            applet.set('view engine', controller.engine)
        }

        /// generate routes based on existing view files
        if (fs.existsSync(veiwsFolder)) {
            applet.set('views', veiwsFolder)

            fs.readdirSync(veiwsFolder).forEach((filename) => {
                const viewName = filename.replace(path.extname(filename), '')

                if (!controller[viewName]) {
                    viewGeneratedRoutes[viewName] = filename

                    controller[viewName] = (s, r, res) => {
                        return res.render(viewName)
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
                this.log.info(`[${controllerName}] -> generated routes`)
            }

            // route exports
            switch (key) {
                case 'show':
                    method = 'get'
                    postfix = '/:' + name + '_id'
                    break

                case 'list':
                    method = 'get'
                    postfix = 's'
                    break

                case 'edit':
                    method = 'get'
                    postfix = '/:' + name + '_id/edit'
                    break

                case 'update':
                    method = 'put'
                    postfix = '/:' + name + '_id'
                    break

                case 'create':
                    method = 'post'
                    break

                case 'index':
                    method = 'get'
                    break

                default:
                    /* istanbul ignore next */
                    throw new Error('unrecognized route: ' + name + '.' + key)
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
                handler = this.wrapRequestHandler(this.templateRequestHandler(controller[key]))
            } else {
                handler = this.wrapRequestHandler(controller[key])
            }

            /// before middleware support
            if (controller.before) {
                applet[method](url, this.wrapRequestHandler(controller.before), handler)
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

            this.log.info(
                `[${controllerName}] -> custom routes`,
                Object.keys(this._customRoutesAdded).map((p) => {
                    const functionHeaderSplit = this._customRoutesAdded[p].split(' ')

                    return `${functionHeaderSplit[0].toUpperCase()} ${p} -> ${
                        functionHeaderSplit[1].length > 1 ? functionHeaderSplit[1] : '*'
                    }()`
                }),
            )

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

    routeSubdomainRequest(endpoint, response, method = 'get') {
        endpoint = `${this._customControllerRoutePrefix}${endpoint}`

        const getFunctionName = (func) => {
            // Match:
            // - ^          the beginning of the string
            // - function   the word 'function'
            // - \s+        at least some white space
            // - ([\w\$]+)  capture one or more valid JavaScript identifier characters
            // - \s*        optionally followed by white space (in theory there won't be any here,
            //              so if performance is an issue this can be omitted[1]
            // - \(         followed by an opening brace
            //
            const funcToString = func.toString()
			let result = /^function\s+([\w\$]+)\s*\(/.exec(funcToString)
            result = result ? result[1] : null
            result = result ? result : funcToString.substring(0, funcToString.substr().indexOf('('))

            return result
        }
        const functionName = getFunctionName(response)

        this._customRoutesAdded[endpoint] = `${method} ${functionName}`
        this.app[method](endpoint, this.wrapRequestHandler(response))
    }

    templateRequestHandler(template) {
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
            const data = this.getPublicConfigurationValues(subdomain, host, params)
            return this.renderTemplate(template, data, res)
        }
    }

    wrapRequestHandler(handler) {
        return (req, res, next) => {
            const subdomain = _getSubdomainPrefix(this.config, req)
            const host = req.headers.host
            const url = req.url
            const ignoreRequests = [
                '/public*',
                '/css*',
                '/js*',
                '/font*',
                '/webfont*',
                '/img*',
                '/media*',
            ]
            if (!new RegExp(ignoreRequests.join('|')).test(url)) {
                const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress

                log.status(`incoming [${req.method}] request`, {
                    url,
                    subdomain,
                    ip,
                })
            }

            return handler.call({app: this}, subdomain, req, res, host, next)
        }
    }

    renderTemplate(template, data, res) {
        const pageTemplate = path.join(this.config.templatesFolder, template, 'index')

        if (this.config.supportRendering && fs.existsSync(`${pageTemplate}.ejs`)) {
            log.debug('rendering template', { data, pageTemplate })
            return res.render(pageTemplate, data)
        }

        const pageFile = `${pageTemplate}.html`
        if (fs.existsSync(pageFile)) {
            log.status('serving html file', pageFile)
            return res.sendFile(pageFile)
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

    getPublicConfigurationValues(subdomain, host, overrides) {
        return _getPublicConfigurationValues(this.config, subdomain, host, overrides)
    }

    getTemplateNameFromSubdomain(subdomain) {
        return _getTemplateNameFromSubdomain(this.config, subdomain)
    }

    getSubdomainOpts(req) {
        const subdomain =
            (typeof req).toLocaleLowerCase() === 'string'
                ? req
                : _getSubdomainPrefix(this.config, req, true)

        return _getSubdomainOpts({ ...this.config, hostname: req.hostname }, subdomain)
    }

    getSubdomainFromAlias(alias) {
        return _getSubdomainFromAlias(this.config, alias)
    }

    isValidRequestOrigin(req) {
        /// All requests should match this host
        const host = this.config.host

        const origin = req.get('origin') || 'none'
        const subdomain = _getSubdomainPrefix(this.config, req, true)
        const subdomainPrefix = `${subdomain == 'default' ? '' : `${subdomain}.`}`
        const path = ''
        const protocol = req.protocol
        const reconstructedUrl = `${protocol}://${subdomainPrefix}${host}${path}`

        const localhostPortIsTheSameForDebugging =
            origin === reconstructedUrl || origin === `${reconstructedUrl}:${this.config.port}`
        const originIsCorrectSubdomain = origin == `${protocol}://${subdomainPrefix}${host}`
        const originIsValid = originIsCorrectSubdomain || localhostPortIsTheSameForDebugging

        if (originIsValid) {
            this.log(`origin ${origin} is valid`)
        } else {
            log.error(`origin ${origin} is not valid`, {
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

    /// Begin application initialization
    init() {
        this.log.debug(this.config.initSeqMessage)

        /// Set up request sessions
        this.app.use(
            session({
                secret: this.config.appName,
                resave: false,
                saveUninitialized: false,
            }),
        )
        /// Initialize and configure passportjs for maintaining connections to third party auth's
        this.app.use(passport.initialize(this.config.passport ? this.config.passport : {}))
        this.app.use(passport.session({}))

        /// Support JSON-encoded bodies
        this.app.use(express.json())
		this.app.set('json spaces', 2)

        /// Support URL-encoded bodies
        this.app.use(
            express.urlencoded({
                extended: true,
            }),
        )

        /// Discover and add the favicon
        const faviconFileName = path.join(this.config.publicFolder, 'favicon.ico')
        if (fs.existsSync(faviconFileName)) {
            this.log.info('favicon found', faviconFileName)
            this.app.use(favicon(faviconFileName))
        } else {
            this.log.error('favicon not found', faviconFileName)
        }

        /// TODO: Add init middlewares
    }

    /// Initializes the app's cache
    cache() {
        this.cache = new nodeCache({
            stdTTL: this.config.cacheTTL ? this.config.cacheTTL : 60000,
        })
    }

    /// Attaches an httpcode error handler template
    async errors() {
        if (!this.config.debug) {
            let css, template
            const templatesErrorFolder = path.join(this.config.templatesFolder, 'error')

            if (fs.existsSync(templatesErrorFolder)) {
                const cssFilePath = path.join(templatesErrorFolder, 'error.css')
                const templateFilePath = path.join(templatesErrorFolder, 'template.ejs')

                // if (fs.existsSync(cssFilePath)) {
                // 	css = cssFilePath
                // 	this.log.info('using custom css file for error pages', cssFilePath)
                // }
                if (fs.existsSync(templateFilePath)) {
                    template = templateFilePath
                    this.log.info('using custom css file for error pages', templateFilePath)
                }
            }

            const errorDataHandler = !this.config.headless
                ? (data, req) => {
                      data.redirectTo = `${req.protocol}://${req.get('host')}`
                      return data
                  }
                : undefined

            // use http error pages handler (final statement!)
            await httpErrorPages.express(this.app, {
                errorDataHandler,
                logger: console.error,
                template,
                css,
                lang: this.config.lang || 'en_US',
                footer: `Care of <strong>${this.config.appName}</strong>`,
            })
        }
    }

    docs() {
        if (this.config.documentAPI) {
            const swaggerUi = require('swagger-ui-express')
            const swaggerJSDoc = require('swagger-jsdoc')
			const apiDocsEndpoint = '/api/docs'
			// const apiDocsTemplateDestination = path.resolve(this.config.templatesFolder, 'docs')

			/// TODO: send to temporary folder to archive into a .zip file that can be downloaded from the api/docs path alongside the swagger.json
			// const swaggerServerCodegen = require('swagger-node-codegen')

			/// Generate the clientside code to consume the API
			// const swaggerClientCodegen = require('swagger-codegen')
			
			const getSwaggerSpec = (opts, host) => {
                const swaggerDefinition = {
                    info: {
                        title: opts.title,
                        version: opts.version,
                        description: opts.description,
                    },
                    host: host || opts.host,
                }
                const options = {
                    swaggerDefinition,
                    apis: _getControllers(opts),
                }
                return swaggerJSDoc(options)
			}

            this.app.use(apiDocsEndpoint, swaggerUi.serve)
            this.app.get(apiDocsEndpoint, (req, res, next) => {
				const swaggerSpec = getSwaggerSpec(this.config, `${req.hostname}/api`)

                return swaggerUi.setup(swaggerSpec)(req, res, next)
            })
            this.app.get(`${apiDocsEndpoint}/swagger.json`, (req, res) => {
				const swaggerSpec = getSwaggerSpec(this.config, `${req.hostname}/api`)
				
                return res.json(swaggerSpec)
            })

			// const clientsideCode = swaggerClientCodegen({
			// 	swagger: getSwaggerSpec(this.config),
				// Templates that run per #/definition
				// perDefinition: {
				//   // Substitute for your own handlebars template
				//   // and generate as many as you want.
				//   './path/to/def-template.hbs': {
				// 	target: './target-folder',
				// 	extension: '.js', // Default
				// 	/* Add your own options for templates here */
				//   }
				// },
			  
				// // Templates that run per grouping of 
				// // path attributes
				// perPath: {
				//   // Substitute for your own handlebars template
				//   // and generate as many as you want.
				//   './path/to/def-template.hbs': {
				// 	groupBy: 'x-swagger-router-controller',
				// 	target: './controllers',
				// 	extension: '.js', // Default
				// 	operations: ['get', 'put', 'post', 'delete'], // Default
				// 	/* Add your own options for templates here */
				//   }
				// }
			// 	failureHandler: e => console.error(e),
			//   })

			/// Copy the swagger-client dist to our templates/base folder
			const swaggerClientJsFilePath = path.join(__dirname, '..', 'node_modules', 'swagger-client', 'dist')
			if (fs.existsSync(swaggerClientJsFilePath)) {
				const minifiedFile = 'swagger-client.browser.min.js'
				const mapFile = `${minifiedFile}.map`
				const minifiedFilePath = path.join(swaggerClientJsFilePath, minifiedFile)
				const mapFilePath = path.join(swaggerClientJsFilePath, mapFile)
				const destinationFolder = path.join(this.config.publicFolder, 'js')

				if (fs.existsSync(minifiedFilePath) && fs.existsSync(mapFilePath)) {
					const destMinifiedFile = `${this.config.appName}-api.js`
					const destMapFile = `${destMinifiedFile}.map`

					mkdirp.sync(destinationFolder)
					fs.copyFileSync(minifiedFilePath, path.join(destinationFolder, destMinifiedFile))
					fs.copyFileSync(mapFilePath, path.join(destinationFolder, destMapFile))

					this.log.info(`Copied the swagger-client dist to our templates/base folder`, {
						destinationFolder,
						minifiedFile,
						mapFile,
					})
				} else {
					this.log.info(`The swagger-client package dist files could not be found`, {
						swaggerClientJsFilePath,
						minifiedFile,
						mapFile,
					})
				}
			} else {
				this.log.info(`The swagger-client package could not be found`, {swaggerClientJsFilePath})
			}

			//   console.log({clientsideCode})
			// swaggerServerCodegen.generate({
			// 	swagger: getSwaggerSpec(this.config),
			// 	target_dir: apiDocsTemplateDestination,
			// }).then(() => {
			// 	this.log.info(`API template generated`, apiDocsTemplateDestination)
			// }).catch(err => {
			// 	this.log.error(`API template generation failed: ${err.message}`);
			// })
            this.log.info(`Running API documentation at route`, [apiDocsEndpoint])
        }
    }

    /// Sets up internal and external logging
    logging() {
        if (this.config.onlyLogErrors) {
            this.app.use(
                logger('combined', {
                    skip: function (req, res) {
                        return res.statusCode < 400
                    },
                }),
            )
        } else {
            this.app.use(logger(this.config.debug ? 'dev' : 'tiny'))
        }
    }

    /// Injects security into protected endpoints
    security() {
        this.app.all(
            '/*',
            this.wrapRequestHandler((subdomain, req, res, host, next) => {
                const url = req.url

                this.log.debug('security check', {
                    host,
                    subdomain,
                    url,
                })

                // CORS headers
                res.header('Access-Control-Allow-Origin', '*') // restrict it to the required domain
                res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,OPTIONS')
                // Set custom headers for CORS
                res.header(
                    'Access-Control-Allow-Headers',
                    'Content-type,Accept,X-Access-Token,X-Key',
                )

                if (req.method == 'OPTIONS') {
                    log.error('failed security check!', url)
                    res.status(200).end()
                } else {
                    next()
                }
            }),
        )

        this.log.info('request security enabled')
    }

    /// Adds dynamic routing functionality to the application
    routers() {
        const importcontrollersFolder = (folder, importAll = false) => {
            const indexjs = 'index.js'
            const controllers = fs.readdirSync(folder)

            /// Run index.js in this folder first before anything else
            controllers.sort((a, b) => (a === indexjs ? 1 : b === indexjs ? -1 : 0))
            controllers.forEach((filename) => {
                const file = path.join(folder, filename)

                /// Import all folders under this folder
                if (fs.statSync(file).isDirectory()) {
                    if (importAll) importcontrollersFolder(path.join(folder, filename))

                    return
                }

                /// Import only index.js files
                if (filename.indexOf(indexjs) === -1) return

                const controller = require(file)
                this.addController(
                    controller,
                    folder.replace(this.config.controllersFolder, '').length > 1
                        ? folder.substring(folder.lastIndexOf('/') + 1)
                        : '',
                )
            })
        }

        if (fs.existsSync(this.config.controllersFolder)) {
            importcontrollersFolder(this.config.controllersFolder, true)
        }
    }

    /// Adds templating to the app using ejs by default
    templating(supportRendering = true) {
        /// TODO: make this a configurable feature
        this.config.supportRendering = supportRendering

        if (this.config.supportRendering) {
            //Set view engine to ejs
            this.app.set('view engine', 'ejs')

            //Tell Express where we keep our index.ejs
            // this.app.set("views", path.join(__dirname, "templates"))

            //Use body-parser
            this.app.use(
                bodyParser.urlencoded({
                    extended: false,
                }),
            )
        }

        if (!!this.config.subdomains) {
            let indexHandler = () => {}
            if (this.config.headless) {
                this.log.info('head requests will return 404')
                indexHandler = (subdomain, req, res, host, next) => {
                    const error = new Error('No head template')
                    error.status = 404
                    next(error)
                }
            } else {
                this.log.info('routing all basepath requests to configued templates')
                indexHandler = (subdomain, req, res, host, next) => {
                    const template = this.getTemplateNameFromSubdomain(subdomain)
                    return this.templateRequestHandler(template)(subdomain, req, res, host, next)
                }
            }
            /// Final catchall for templated routes
            this.routeSubdomainRequest('/', indexHandler)

            Object.keys(this.config.subdomains).forEach((subdomain) => {
                if (!!this.config.subdomains[subdomain]) {
                    const subdomainTemplate = this.config.subdomains[subdomain].template

                    if (!!subdomainTemplate) {
                        const subdomainTemplatePath = path.join(
                            this.config.templatesFolder,
                            subdomainTemplate,
                        )

                        if (fs.existsSync(subdomainTemplatePath)) {
                            this.log.debug(
                                `configuring static path for subdomain: ${subdomain}`,
                                subdomainTemplatePath,
                            )
                            this.app.use(express.static(subdomainTemplatePath))
                        } else {
                            this.log.error('subdomain template not found', {
                                subdomain,
                                subdomainTemplatePath,
                            })
                        }
                    } else {
                        this.log.error('subdomain template not set', {
                            subdomain,
                        })
                    }
                } else {
                    this.log.error('cannot configure subdomain', subdomain)
                }
            })
        }

        // All public content
        this.app.use('/public', express.static(this.config.publicFolder))
        this.log.info('static route configured for public folder', this.config.publicFolder)

        const baseOverride = path.join(this.config.templatesFolder, 'base')
        this.log.debug(`configuring static path for the base override files`, baseOverride)
        this.app.use(express.static(baseOverride))

        /// DEPRECATED this should have already been handled by the static path usage above, but wasn't previously
        // this.app.use("/public", (req, res) => {
        // 	this.log.debug("asset requested", req.url)
        // 	const file = (req.url =
        // 		req.url.indexOf("?") != -1 ?
        // 		req.url.substring(0, req.url.indexOf("?")) :
        // 		req.url)
        // 	return res.sendFile(
        // 		path.join(this.config.publicFolder, req.url)
        // 	)
        // })

        this.log.debug('finished templating set up for path', this.config.templatesFolder)
    }

    /// Handles OATH requests for authenticating with third-party APIs
    authentication() {
        passport.serializeUser((user, done) => {
            done(null, user)
        })

        passport.deserializeUser((obj, done) => {
            done(null, obj)
        })

        if (this.config.defaults.imgurClientID) {
            log.info(
                'configuring imgur API authentication for appID:',
                this.config.defaults.imgurClientID,
            )

            const self = this
            const setImgurTokens = function (accessToken, refreshToken, profile) {
                for (const subdomain of subdomains) {
                    authTokens[subdomain].imgur.imgurAccessToken = accessToken
                    authTokens[subdomain].imgur.imgurRefreshToken =
                        authTokens[subdomain].imgur.imgurRefreshToken || refreshToken
                    authTokens[subdomain].imgur.imgurProfile =
                        authTokens[subdomain].imgur.imgurProfile || profile
                    self.log(
                        `imgur authentication information for subdomain: subdomain`,
                        authTokens[subdomain].imgur,
                    )
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
                    self.log('imgur auth callback with valid profile', profile)
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
            const refreshImgurTokens = function () {
                const theRefreshTokenToUse = authTokens.default.imgur.imgurRefreshToken
                self.log.status(
                    'attempting to refresh imgur access token using the refresh token:',
                    theRefreshTokenToUse,
                )
                refresh.requestNewAccessToken(
                    'imgur',
                    theRefreshTokenToUse,
                    (err, accessToken, refreshToken) => {
                        log('imgur access token has been refreshed:', refreshToken)
                        setImgurTokens(accessToken, refreshToken, null)
                    },
                )
            }
            setInterval(refreshImgurTokens, imgurRefreshFrequency)

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
                const subdomain = _getSubdomainPrefix(config, req)
                const response = {
                    imgurAlbumHash: this.config.subdomains[subdomain].imgur.imgurAlbumHash,
                    imgurAuthorization: this.config.subdomains[subdomain].imgur.imgurAuthorization,
                }
                self.log.debug({
                    imgurApiResponse: response,
                })

                if (this.isValidRequestOrigin(req)) {
                    response.imgurRefreshToken = authTokens[subdomain].imgur.imgurRefreshToken
                    response.imgurAccessToken = authTokens[subdomain].imgur.imgurAccessToken
                    response.imgurProfile = authTokens[subdomain].imgur.imgurProfile
                }

                // This will only return the imgur access token if the request is coming from the site itself
                return res.json(response)
            })
        } else {
            this.app.get('/auth/imgur/*', (req, res) => {
                return res.send("I don't have imgur data set in my configuration")
            })
            this.app.post('/auth/*', (req, res) => {
                return res.json({})
            })
        }

        if (this.config.defaults.redditClientID) {
            this.log.info(
                'configuring reddit API authentication for appID:',
                this.config.defaults.redditClientID,
            )

            const setRedditTokens = function (accessToken, refreshToken, profile) {
                // FOR DOMAIN SPECIFIC USER ACCOUNTS ( DO NOT DELETE )
                // var subdomain = getSubdomainPrefix(config, req)

                // authTokens["imgur"][subdomain].imgurRefreshToken = refreshToken
                // authTokens["imgur"][subdomain].imgurAccessToken = accessToken
                // authTokens["imgur"][subdomain].imgurProfile = profile

                for (const subdomain of subdomains) {
                    self.log('setting reddit authentication information for subdomain:', subdomain)
                    authTokens[subdomain].reddit.redditAccessToken = accessToken
                    authTokens[subdomain].reddit.redditRefreshToken =
                        authTokens[subdomain].reddit.redditRefreshToken || refreshToken
                    authTokens[subdomain].reddit.redditProfile =
                        authTokens[subdomain].reddit.redditProfile || profile
                    authTokens[subdomain].reddit.redditUserName =
                        authTokens[subdomain].reddit.redditUserName || profile.name
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
                    self.log.debug('reddit auth callback with valid profile', profile)
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
            const refreshRedditTokens = function () {
                const theRefreshTokenToUse = authTokens.default.reddit.redditRefreshToken
                self.log.status(
                    'attempting to refresh reddit access token using the refresh token:',
                    theRefreshTokenToUse,
                )
                refresh.requestNewAccessToken(
                    'reddit',
                    theRefreshTokenToUse,
                    (err, accessToken, refreshToken) => {
                        self.log('reddit access token has been refreshed:', refreshToken)
                        setRedditTokens(accessToken, refreshToken, null)
                    },
                )
            }
            setInterval(refreshRedditTokens, redditRefreshFrequency)

            passport.use(redditStrategy)
            refresh.use(redditStrategy)

            // Reddit OAuth2 Integration
            this.app.get('/auth/reddit', (req, res, next) => {
                req.session.state = crypto.randomBytes(32).toString('hex')
                self.log('authenticating')
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
                const subdomain = _getSubdomainPrefix(config, req)
                let tokensValue = 'unauthorized access'

                if (this.isValidRequestOrigin(req)) {
                    tokensValue = {
                        redditRefreshToken: authTokens[subdomain].reddit.redditRefreshToken,
                        redditAccessToken: authTokens[subdomain].reddit.redditAccessToken,
                        redditProfile: authTokens[subdomain].reddit.redditProfile,
                    }
                }

                // This will only return the reddit access token if the request is coming from the site itself
                return res.json({
                    redditTokens: tokensValue,
                })
            })
        } else {
            this.app.get('/auth/reddit/*', (req, res) => {
                const responseMessage = "I don't have reddit data set in my configuration"
                res.send(responseMessage)
            })
            this.app.post('/auth/*', (req, res) => {
                return res.json({})
            })
        }
    }

    /// Protects connections to the server with an ssl certificate
    ssl(serverOpts) {
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
    debug() {
        const reloadServer = reload(this.app)
        const watchPath = getRootPath('templates')

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

    /// Runs the express (wr)app with all of the middleware configured
    run(
        started = () => {
            this.log.info(`App listening on: http://${this.config.host}:${this.config.port}`)
        },
    ) {
        this.log.info(`running sexpress on port`, this.config.port)

        this.app.set('port', this.config.port)
        let httpsServer = null,
            serverOpts = {}

        const httpServer = http.createServer(serverOpts, this.app)

        if (
            !this.config.noSSL &&
            !!this.config.ssl &&
            (!!this.config.ssl.passphrase || !!this.config.ssl.strategy)
        ) {
            httpsServer = this.ssl(serverOpts)
        }

        if (this.config.debug) {
            this.debug()
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
                .listen(this.app.get('sslport'), () => {
                    this.log.info(
                        `App listening on: https://${this.config.host}:${this.config.port}`,
                    )
                })
                .on('error', (e) => errorHandler(e, 'HTTPS server error'))
        }
    }
}

module.exports = Sexpress
