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
let config = require('clobfig')()

const { getRootPath, log, logger, merge, getValuesFromObjectOrDefault } = require('./util')(
    config.AppRoot,
)

const packageJsonPath = getRootPath('package.json')
const { setInterval } = require('safe-timers')
const { Strategy: ImgurStrategy } = require('passport-imgur')
const { Strategy: RedditStrategy } = require('passport-reddit')
const util = require('./util')
const { version } = fs.existsSync(packageJsonPath)
    ? require(packageJsonPath)
    : {
          version: 'null',
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

/// TODO: refactor this request to only use the data from the data folder, with whatever else is required, instead of chunking out the data from the config
const getPublicConfigurationValues = (opts, subdomain, host) => {
    const publicConfig = {
        host,
        SUBDOMAIN: subdomain.toUpperCase(),
        thisSubdomain: subdomain,
        debug: opts.debug,
        content: opts.content,
    }

    publicConfig.subdomains = Object.values(opts.subdomains).reduce(
        (out, subdomainInformation, index) => {
            const subdomainName = subdomains[index]
            const customCssPath = path.join(__dirname, 'assets/css', `${subdomain}.css`)
            const pageData = getValuesFromObjectOrDefault(
                opts.publicConfigFields,
                subdomainInformation,
                opts,
            )

            pageData.hasCustomCss = fs.existsSync(customCssPath)
            out[subdomainName] = pageData

            if (subdomain === subdomainName) {
                publicConfig.page = pageData
            }

            return out
        },
        {},
    )

    publicConfig.content = opts.content

    return opts.publicConfigFilter(publicConfig, opts, subdomain)
}

const getSubdomainPrefix = (opts, req, returnAlias = false) => {
    const defaultSubdomain = req.subdomains.length ? req.subdomains[0] : 'default'
    const localhostSubdomainEnd = !!req.headers.host ? req.headers.host.indexOf('.') : -1
    const localhostOverride =
        localhostSubdomainEnd !== -1 ? req.headers.host.substr(0, localhostSubdomainEnd) : null
    const alias = !!localhostOverride ? localhostOverride : defaultSubdomain

    return returnAlias ? alias : getSubdomainFromAlias(opts, alias)
}

const getSubdomainOpts = (opts, req) => {
    const subdomain = getSubdomainPrefix(opts, req, true)
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
        requestHost: req.hostname,
    }
}

const getSubdomainFromAlias = (opts, alias) => {
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

function getTemplateNameFromSubdomain(opts, subdomain) {
    if (!!opts.subdomains[subdomain]) {
        return opts.subdomains[subdomain].template
    }

    return null
}

const isValidRequestOrigin = (opts, req) => {
    /// All requests should match this host
    const host = opts.host

    const origin = req.get('origin') || 'none'
    const subdomain = getSubdomainPrefix(opts, req, true)
    const subdomainPrefix = `${subdomain == 'default' ? '' : `${subdomain}.`}`
    const path = ''
    const protocol = req.protocol
    const reconstructedUrl = `${protocol}://${subdomainPrefix}${host}${path}`

    const localhostPortIsTheSameForDebugging =
        origin === reconstructedUrl || origin === `${reconstructedUrl}:${opts.port}`
    const originIsCorrectSubdomain = origin == `${protocol}://${subdomainPrefix}${host}`
    const originIsValid = originIsCorrectSubdomain || localhostPortIsTheSameForDebugging

    if (originIsValid) {
        log(`origin ${origin} is valid`)
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

async function sendEmail(opts, to, subject, text, callback, html, from) {
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
        ;(transporterOpts.secure = secure), // true for 465, false for other ports
            (transporterOpts.auth = auth)
    }
    const transporter = nodemailer.createTransport(transporterOpts)

    // send mail with defined transport object
    const info = await transporter.sendMail(emailOpts)

    log(`Message sent: ${info.messageId}`)

    if (!configEmailAddressIsSet) {
        // Preview only available when sending through an Ethereal account
        log(`Preview URL: ${nodemailer.getTestMessageUrl(info)}`)
        // Preview URL: https://ethereal.email/message/WaQKMgKddxQDoou...
    }

    return callback(info)
}

const defaults = {
    host: 'localhost',
    run: false,
    initSeqMessage: 'Sexy Configuration!',
    publicConfigFilter: (c) => c,
    includeDefaultPublicConfigFields: true,
    publicConfigFields: [],
}

class Sexpress {
    constructor(opts = {}) {
        this.app = express()
        this.setConfiguration({
            ...defaults,
            ...config,
            ...opts,
        })
        this._customRoutesAdded = []
        this._customControllerRoutePrefix = ''

        this.log = log.setDebugging(this.config.debug)
        this.log.debug(this.config.initSeqMessage, this.config)

        /// TODO: Allow this process to be configurable
        this.init()
        this.logging()
        this.security()
        this.routers()
        this.templating()
        this.authentication()

        if (this.config.run) {
            this.run()
        }
    }

    setConfiguration(config) {
        this.config = config

        this.config.defaults = this.config.defaults || {}
        this.config.staticFolders = this.config.staticFolders || []
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
        this.config.controllerFolder = this.config.controllerFolder
            ? this.config.controllerFolder
            : getRootPath('controllers')
        this.config.viewsFolder = this.config.viewsFolder
            ? this.config.viewsFolder
            : getRootPath('views')
        this.config.getRootPath = getRootPath

        if (this.config.includeDefaultPublicConfigFields) {
            this.config.publicConfigFields.concat([
                'images',
                'adminEmailAddresses',
                'metaUrl',
                'metaType',
                'metaTitle',
                'metaDescription',
                'gaUA',
            ])
        }

        for (const subdomain of subdomains) {
            const subdomainConfiguration = this.config.subdomains[subdomain]

            // Assign the subdomain based imgur authorization information, or use the default
            subdomainConfiguration.imgur = getValuesFromObjectOrDefault(
                ['imgurClientID', 'imgurClientSecret', 'imgurCallbackURL', 'imgurEmailAddress'],
                subdomainConfiguration.imgur,
                this.config.defaults,
                this.config,
            )
            // Assign the subdomain based AWS S3 authorization information, or use the default
            subdomainConfiguration.s3 = getValuesFromObjectOrDefault(
                ['AwsCdnUrl', 'emailAddress', 'accessKeyId', 'secretAccessKey', 'region'],
                subdomainConfiguration.s3,
                this.config.defaults,
                this.config,
            )
            // Assign the subdomain based Reddit authorization information, or use the default
            subdomainConfiguration.reddit = getValuesFromObjectOrDefault(
                [
                    'redditClientID',
                    'redditClientSecret',
                    'redditCallbackURL',
                    'redditUserName',
                    'redditUserAgent',
                    'redditPassword',
                ],
                subdomainConfiguration.reddit,
                this.config.defaults,
                this.config,
            )
            // Assign the subdomain based email authorization information, or use the default
            subdomainConfiguration.email = getValuesFromObjectOrDefault(
                [
                    'emailAccountHost',
                    'emailService',
                    'emailAccountAddress',
                    'emailAccountPassword',
                    'emailAccountIsSecure',
                    'emailAccountPort',
                ],
                subdomainConfiguration.email,
                this.config.defaults,
                this.config,
            )

            authTokens[subdomain] = subdomainConfiguration
        }

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

    init() {
        this.log.debug(this.config.initSeqMessage)

        this.app.use(
            session({
                secret: this.config.appName,
                resave: false,
                saveUninitialized: false,
            }),
        )
        this.app.use(passport.initialize(this.config.passport ? this.config.passport : {}))
        this.app.use(passport.session({}))
        this.app.use(express.json()) // to support JSON-encoded bodies
        this.app.use(
            express.urlencoded({
                extended: true,
            }),
        ) // to support URL-encoded bodies

        const faviconFileName = path.join(__dirname, 'public/', 'favicon.ico')
        if (fs.existsSync(faviconFileName)) {
            this.app.use(favicon(faviconFileName))
        }
    }

    addController(controller, name = '') {
        name = controller.name ? controller.name : name
        const prefix = `/${controller.prefix ? controller.prefix : name}`
        const applet = express()
        const veiwsFolder = path.join(this.config.controllerFolder, name, 'views')
        const viewGeneratedRoutes = []

        if (!name) {
            controller.useRootPath =
                typeof controller.useRootPath !== 'undefined' ? controller.useRootPath : true
        }

        this.log.info(`loading controller: ${name ? name : 'default'}`)

        let handler,
            method,
            postfix = '',
            pathMessage

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
            pathMessage = `     ${method.toUpperCase()} ${url} -> ${key}`

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

            this.log.info(pathMessage)
        }

        // middleware custom routes
        if (!!controller.routes) {
            this._customControllerRoutePrefix = controller.useRootPath ? '' : prefix

            const thisApp = this.app
            /// use the applet for the controller routes
            this.app = applet
            controller.routes(this)
            /// reset back to the main app
            this.app = thisApp

            this.log.info('loaded custom routes', this._customRoutesAdded)

            this._customRoutesAdded = []
            this._customControllerRoutePrefix = ''
        }

        // mount the app
        this.app.use(applet)
    }

    use(handler, handler2) {
        return this.app.use(handler, handler2)
    }

    routeSubdomainRequest(endpoint, response, method = 'get') {
        endpoint = `${this._customControllerRoutePrefix}${endpoint}`

        this._customRoutesAdded[endpoint] = method
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

            const data = this.getPublicConfigurationValues(subdomain, host)
            return this.renderTemplate(template, data, res)
        }
    }

    wrapRequestHandler(handler) {
        return (req, res, next) => {
            const subdomain = getSubdomainPrefix(this.config, req)
            const host = req.headers.host
            const url = req.url
            const ignoreRequests = ['/public*', '/css*', '/js*', '/img*', '/media*']
            if (!new RegExp(ignoreRequests.join('|')).test(url)) {
                const ip = req.headers['x-forwarded-for'] || req.connection.remoteAddress

                log.status('incoming request', {
                    url,
                    subdomain,
                    ip,
                })
            }

            return handler(subdomain, req, res, host, next)
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

        log('could not render template', template)
    }

    sendEmail(subdomainConfig, opts = {}) {
        return sendEmail(
            !!subdomainConfig ? subdomainConfig : this.config,
            opts.to,
            opts.subject,
            opts.text,
            opts.callback,
            opts.html,
            opts.from,
        )
    }

    getPublicConfigurationValues(subdomain, host) {
        return getPublicConfigurationValues(this.config, subdomain, host)
    }

    getTemplateNameFromSubdomain(subdomain) {
        return getTemplateNameFromSubdomain(this.config, subdomain)
    }

    getSubdomainOpts(req) {
        return getSubdomainOpts(this.config, req)
    }

    getSubdomainFromAlias(alias) {
        return getSubdomainFromAlias(this.config, alias)
    }

    isValidRequestOrigin(req) {
        return isValidRequestOrigin(this.config, req)
    }

    logging() {
        this.log = this.log.setDebugging(this.config.debug)

        this.app.use(logger('dev'))
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

    /// adds project functionality to the application
    routers() {
        const importControllerFolder = (folder, importAll = false) => {
            const indexjs = 'index.js'
            const controllers = fs.readdirSync(folder)

            /// Run index.js in this folder first before anything else
            controllers.sort((a, b) => (a === indexjs ? 1 : b === indexjs ? -1 : 0))
            controllers.forEach((filename) => {
                const file = path.join(folder, filename)

                /// Import all folders under this folder
                if (fs.statSync(file).isDirectory()) {
                    if (importAll) importControllerFolder(path.join(folder, filename))

                    return
                }

                /// Import only index.js files
                if (filename.indexOf(indexjs) === -1) return

                const controller = require(file)
                this.addController(
                    controller,
                    folder.replace(this.config.controllerFolder, '').length > 1
                        ? folder.substring(folder.lastIndexOf('/') + 1)
                        : '',
                )
            })
        }

        if (fs.existsSync(this.config.controllerFolder)) {
            importControllerFolder(this.config.controllerFolder, true)
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
            this.routeSubdomainRequest('/', (subdomain, req, res, host, next) => {
                const template = this.getTemplateNameFromSubdomain(subdomain)
                return this.templateRequestHandler(template)(subdomain, req, res, host, next)
            })

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

            const setImgurTokens = function (accessToken, refreshToken, profile) {
                for (const subdomain of subdomains) {
                    authTokens[subdomain].imgur.imgurAccessToken = accessToken
                    authTokens[subdomain].imgur.imgurRefreshToken =
                        authTokens[subdomain].imgur.imgurRefreshToken || refreshToken
                    authTokens[subdomain].imgur.imgurProfile =
                        authTokens[subdomain].imgur.imgurProfile || profile
                    log(
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
                    log('imgur auth callback with valid profile', profile)
                    setImgurTokens(accessToken, refreshToken, profile)
                    return done(null, profile)
                    // }
                    /// TODO: make this error checking more accurate
                    // Someone else wants to authorize our app? Why?
                    // console.error(
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
                log(
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
                const subdomain = getSubdomainPrefix(config, req)
                const response = {
                    imgurAlbumHash: this.config.subdomains[subdomain].imgur.imgurAlbumHash,
                    imgurAuthorization: this.config.subdomains[subdomain].imgur.imgurAuthorization,
                }
                log({
                    imgurApiResponse: response,
                })

                if (isValidRequestOrigin(this.config, req)) {
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
            log.info(
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
                    log('setting reddit authentication information for subdomain:', subdomain)
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
                    log('reddit auth callback with valid profile', profile)
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
                log(
                    'attempting to refresh reddit access token using the refresh token:',
                    theRefreshTokenToUse,
                )
                refresh.requestNewAccessToken(
                    'reddit',
                    theRefreshTokenToUse,
                    (err, accessToken, refreshToken) => {
                        log('reddit access token has been refreshed:', refreshToken)
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
                log('authenticating')
                passport.authenticate('reddit', {
                    state: req.session.state,
                    duration: 'permanent',
                })(req, res, next)
            })
            this.app.get('/auth/reddit/callback', (req, res, next) => {
                // Check for origin via state token
                if (req.query.state == req.session.state) {
                    // log("passporting")
                    passport.authenticate('reddit', {
                        successRedirect: '/',
                        failureRedirect: '/fail',
                    })(req, res, next)
                } else {
                    // log("Error 403")
                    next(new Error(403))
                }
            })
            this.app.post('/auth/reddit/getToken', (req, res) => {
                const subdomain = getSubdomainPrefix(config, req)
                let tokensValue = 'unauthorized access'
                // log("getting token")

                if (isValidRequestOrigin(this.config, req)) {
                    // log("request is valid")
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
                // log(responseMessage)
                res.send(responseMessage)
            })
            this.app.post('/auth/*', (req, res) => {
                return res.json({})
            })
        }
    }

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

    debug() {
        const reloadServer = reload(this.app)
        const watchPath = getRootPath('templates')

        if (fs.existsSync(watchPath)) {
            watch.watchTree(watchPath, (f, curr, prev) => {
                log('Asset change detected, reloading connection')
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
            log.info(`App listening on: http://${this.config.host}:${this.config.port}`)
        },
    ) {
        log.info(`running sexpress on port`, this.config.port)

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

        if (!!httpServer) {
            httpServer.listen(this.app.get('port'), started)
        }

        if (!!httpsServer) {
            httpsServer.listen(this.app.get('sslport'), () => {
                log.info(`App listening on: https://${this.config.host}:${this.config.port}`)
            })
        }
    }
}

module.exports = Sexpress
