const namespace = 'Utilities'
let singleton

class util {
    constructor(utilOpts = {}) {
        const merge = require('deepmerge')
        const { setInterval } = require('safe-timers')

        /// We don't care about the value, though, this middleware will always be initialized
        utilOpts = typeof utilOpts === 'boolean' ? {} : utilOpts

        /// Ensure the basics are set
        utilOpts = merge(
            {
                AppRoot: require('app-root-path'),
                log: console.log,
            },
            utilOpts,
        )

        this.appRoot = utilOpts.AppRoot
        this.log = this.wrapLogger(utilOpts.log)

        /// Externals (may not be used internally)
        this.fs = utilOpts.fs || require('fs')
        this.path = utilOpts.path || require('path')
        this.chalk = utilOpts.chalk || require('chalk')
        this.cliProgress = utilOpts.cliProgress || require('cli-progress')
        this.ora = utilOpts.ora || require('ora')
        this.merge = utilOpts.merge || merge
        this.logger = utilOpts.logger || require('morgan')
        this.mkdirp = utilOpts.mkdirp || require('mkdirp')
        this.setInterval = utilOpts.setInterval || setInterval
    }

    wrapLogger(_logger) {
        _logger.error = _logger.error || _logger

        const error = (message, obj = '') =>
            _logger.error(singleton.instance.chalk.red(message), obj)
        const info = (message, obj = '') =>
            _logger(singleton.instance.chalk.blueBright(message), obj)
        const log = (message, obj = '') => {
            if (obj) _logger(message, obj)
            else _logger(message)
        }
        const prompt = (message, obj = '') => _logger(singleton.instance.chalk.yellow(message), obj)
        const status = (message, obj = '') => _logger(singleton.instance.chalk.cyan(message), obj)
        const success = (message, obj = '') => _logger(singleton.instance.chalk.green(message), obj)
        const debug = (message, obj = '') =>
            _logger(singleton.instance.chalk.blueBright(message), obj)

        const _log = log

        _log.error = error
        _log.info = info
        _log.prompt = prompt
        _log.status = status
        _log.log = log
        _log.success = success
        _log.debug = debug

        _log.setDebugging = function (debugging) {
            this.debug = debugging ? debug : () => {}

            return this
        }.bind(_log)

        return _log
    }

    stringIsExactMatch(string1, string2, caseSensitive = true) {
        const opts = {}

        // negating the default here because it makes the function call look nmore accurate
        if (!caseSensitive) {
            opts.sensitivity = 'base'
        }

        return string1.localeCompare(string2, undefined, opts) === 0
    }

    promiseMe(task) {
        if (!task) return Promise.resolve()

        return new Promise((resolve) => task(resolve))
    }

    getRootPath(paths) {
        if (!Array.isArray(paths)) {
            paths = [paths]
        }

        return singleton.instance.appRoot.resolve(singleton.instance.path.join(...paths))
    }

    getValuesFromObjectOrDefault(
        names,
        input = {},
        defaults = {},
        final = {},
        defaultsOverride = false,
    ) {
        const out = {}
        const defaul = { ...defaults }
        const finale = { ...final }
        names = names || Object.keys(defaults)

        names.forEach((name) => {
            if (defaultsOverride) {
                out[name] =
                    typeof defaul[name] !== 'undefined'
                        ? defaul[name]
                        : !!input[name]
                        ? input[name]
                        : finale[name]
            } else {
                out[name] = !!input[name]
                    ? input[name]
                    : typeof defaul[name] !== 'undefined'
                    ? defaul[name]
                    : finale[name]
            }
        })

        return out
    }

    getSubdomainFromAlias(opts, alias) {
        let baseSubdomain = alias

        Object.keys(opts.subdomains).forEach((baseName) => {
            const aliases = opts.subdomains[baseName].aliases || []

            if (alias === baseName || aliases.indexOf(alias) !== -1) {
                baseSubdomain = baseName
                return
            }
        })

        return baseSubdomain
    }

    getSubdomainPrefix(opts, req, returnAlias = false) {
        const hostname = typeof req === 'string' ? req : req.hostname
        const subdomains = hostname
            .replace(/https?:\/\//gi, '')
            .split('.')
            .reverse()
        const isLocalhost = subdomains[0] === 'localhost'
        const offset = isLocalhost ? 0 : 1

        let baseSubdomain =
            subdomains.length > offset + 1 ? subdomains[offset + 1] : subdomains[offset]

        baseSubdomain =
            opts.host.indexOf(baseSubdomain) === -1
                ? baseSubdomain
                : opts.routing.indexControllerName

        return returnAlias
            ? baseSubdomain
            : singleton.instance.getSubdomainFromAlias(opts, baseSubdomain)
    }

    getControllerNameFromFilePath(controllerFilePath) {
        const fileNameOmitted = controllerFilePath.replace('/index.js', '')

        return fileNameOmitted.substring(fileNameOmitted.lastIndexOf('/') + 1)
    }

    getViews(opts, viewsFolder) {
        const out = {}
        viewsFolder = viewsFolder || opts.folders.viewsFolder

        singleton.instance.fs.readdirSync(viewsFolder).forEach((filename) => {
            if (
                singleton.instance.path.extname(filename) !==
                `.${opts.rendering.overrideViewEngine}`
            )
                return

            const viewName = filename.replace(singleton.instance.path.extname(filename), '')
            out[viewName] = filename
        })

        return out
    }

    getControllers(opts, controllersFolder, ignore) {
        controllersFolder = controllersFolder ? controllersFolder : opts.controllersFolder
        const indexjs = 'index.js'
        const out = []

        const _getControllers = (folder, importAll) => {
            /// Run index.js in this folder first before anything else
            const controllersFiles = singleton.instance.fs.readdirSync(folder)
            controllersFiles.sort((a, b) => (a === indexjs ? -1 : b === indexjs ? 1 : 0))

            controllersFiles.forEach((filename) => {
                const file = singleton.instance.path.join(folder, filename)
                const controllerName = singleton.instance.getControllerNameFromFilePath(folder)

                /// Import all folders under this folder
                if (singleton.instance.fs.statSync(file).isDirectory()) {
                    if (filename !== 'views' && importAll)
                        _getControllers(singleton.instance.path.join(folder, filename))
                    return
                }

                /// Import only index.js files
                if (filename.indexOf(indexjs) === -1) return
                if (ignore && ignore.indexOf(controllerName) !== -1) return

                out.push(singleton.instance.path.join(folder, filename))
            })
        }

        if (singleton.instance.fs.existsSync(controllersFolder)) {
            _getControllers(controllersFolder, true)
        }

        return out
    }

    /// Returns the constructed base URL of the website
    getHostBaseUrl(opts, host, protocol = '', subdomain, fullHost = true) {
        if (typeof host === 'boolean' && protocol === '') {
            fullHost = host
            host = opts.host
        }

        host = !!host ? host : opts.host
        let hostname = host,
            baseUrl = host

        const portPresent = hostname.indexOf(':')
        if (portPresent === -1) {
            hostname = `${host}${opts.port !== 80 || opts.port !== 443 ? `:${opts.port}` : ''}`
        }
        if (subdomain) {
            hostname = `${subdomain}.${hostname}`
        }
        if (fullHost) {
            protocol = protocol ? protocol : opts.protocol || 'http'
            baseUrl = `${protocol ? `${protocol}://` : ''}${hostname}`
        } else {
            baseUrl = baseUrl.replace(/https?:\/\//gi, '')
        }

        return baseUrl
    }

    /// Returns the application endpoint {baseUrl}/api
    getHostUri(opts, host, protocol = '', append = '/api', fullHost = true) {
        return `${singleton.instance.getHostBaseUrl(
            opts,
            host,
            protocol,
            undefined,
            fullHost,
        )}${append}`
    }

    getFromQueryOrPathOrBody(req, name, orThis, parser = (v) => v) {
        const queryParam = parser(req.query[name])
        const pathParam = parser(req.params[name])
        const bodyParam = parser(req.body[name])

        if (!!queryParam) return queryParam
        if (!!pathParam) return pathParam
        if (!!bodyParam) return bodyParam

        return orThis
    }

    getFunctionName(func) {
        // Match:
        // - ^          the beginning of the string
        // - function   the word 'function'
        // - \s+        at least some white space
        // - ([\w\$]+)  capture one or more valid JavaScript identifier characters
        // - \s*        optionally followed by white space (in theory there won't be any here,
        //              so if performance is an issue this can be omitted[1]
        // - \(         followed by an opening brace
        //
        if (!func) return 'passthrough'

        const funcToString = func.toString()
        let result = /^function\s+([\w\$]+)\s*\(/.exec(funcToString)
        result = result ? result[1] : null
        result = result ? result : funcToString.substring(0, funcToString.substr().indexOf('('))

        return result
    }

    isPromise(mightBeAPromise) {
        /// TODO: detect a promise better you noob
        return !!mightBeAPromise //&& (typeof mightBeAPromise).toLocaleLowerCase() === 'promise'
    }

    extractEmails(text) {
        return text.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi)
    }

    consoleLogEmoji(emoji) {
        switch (emoji) {
            case 0:
            case '0':
                emoji = `0️⃣`
                break
            case 1:
            case '1':
                emoji = `1️⃣`
                break
            case 2:
            case '2':
                emoji = `2️⃣`
                break
            case 3:
            case '3':
                emoji = `3️⃣`
                break
            case 4:
            case '4':
                emoji = `4️⃣`
                break
            case 5:
            case '5':
                emoji = `5️⃣`
                break
            case 6:
            case '6':
                emoji = `6️⃣`
                break
            case 7:
            case '7':
                emoji = `7️⃣`
                break
            case 8:
            case '8':
                emoji = `8️⃣`
                break
            case 9:
            case '9':
                emoji = `9️⃣`
                break
        }

        return emoji
    }

    consoleLogEmojiNumber(number) {
        const numberString = number.toString()
        let out = ''
        for (let i = 0; i < numberString.length; ++i) {
            out += singleton.instance.consoleLogEmoji(numberString[i])
        }
        return out
    }

    getServers(
        opts,
        host,
        protocol,
        subdomain,
        forceSecure = false,
        ignoreSubdomains = [],
        isAuthenticated = false,
    ) {
        const servers = []
        protocol = forceSecure ? 'https' : protocol
        ignoreSubdomains =
            typeof ignoreSubdomains === 'string' ? [ignoreSubdomains] : ignoreSubdomains
        ignoreSubdomains.push(opts.routing.indexControllerName)
        const externalServerDescription = `External ${opts.name} application URI`
        const internalServerDescription = `Internal ${opts.name} application URI`

        /// Add the index {host}/api server first, if access is granted
        if (!opts.api.secureApiDocs || isAuthenticated) {
            servers.push({
                url: `${singleton.instance.getHostBaseUrl(opts, opts.host, protocol, '')}/api`,
                description: internalServerDescription,
            })
        }

        if (subdomain === 'api' || subdomain == opts.routing.indexControllerName) {
            // if (subdomain !== 'api') {
            // 	servers.push({
            // 		url: singleton.instance.getHostBaseUrl(opts, opts.host, protocol, 'api'),
            // 		description: internalServerDescription,
            // 	})
            // }
            /// If we are on the index controller or the api controller, show all apis
            Object.keys(opts.subdomains).forEach((sub) => {
                let description = opts.subdomains[sub].description,
                    apiSubPrefix = 'api.',
                    apiHost = `${host}/`

                /// Keep the index subdomain but remove the index from the name
                if (sub === opts.routing.indexControllerName) {
                    sub = ''
                    apiHost = opts.host
                    description = externalServerDescription
                } else if (ignoreSubdomains.indexOf(sub) !== -1) {
                    return
                }

                const url = singleton.instance.getHostUri(
                    opts,
                    `${apiSubPrefix}${apiHost}`,
                    protocol,
                    `/${sub}`,
                    true,
                )

                servers.push({
                    url,
                    description,
                })
            })
        }

        return servers
    }

    findViewFile(opts, view, engine) {
        let foundView = false

        engine = typeof engine === 'undefined' ? opts.rendering.overrideViewEngine : engine
        if (typeof engine === 'array' || typeof engine === 'object') {
            for (const e of engine) {
                if ((foundView = singleton.instance.findViewFile(opts, view, e))) break
            }

            return foundView
        }

        const viewFile = singleton.instance.path.join(opts.folders.viewsFolder, `${view}.${engine}`)

        if (singleton.instance.fs.existsSync(viewFile)) return viewFile

        const viewFileIndex = singleton.instance.path.join(
            opts.folders.viewsFolder,
            `${view}/index.${engine}`,
        )

        if (singleton.instance.fs.existsSync(viewFileIndex)) return viewFileIndex

        return foundView
    }

    findTemplateFile(opts, engine) {
        const viewFile = singleton.instance.path.join(
            opts.folders.templatesFolder,
            `${view}.${engine}`,
        )

        if (singleton.instance.fs.existsSync(viewFile)) return viewFile

        const viewFileIndex = singleton.instance.path.join(
            opts.folders.viewsFolder,
            `${view}/index.${engine}`,
        )

        if (singleton.instance.fs.existsSync(viewFileIndex)) return viewFileIndex

        return false
    }

    injectIntoString(
        haystack,
        needle,
        thread,
        marker = '%%MARKER%%',
        wrapper = (s) => s,
        before = true,
    ) {
        if (typeof haystack === 'object') {
            const opts = haystack
            needle = opts.needle || needle
            thread = opts.thread || thread
            marker = opts.marker || marker
            wrapper = typeof opts.wrapper === 'function' ? opts.wrapper : wrapper
            before = typeof opts.before !== 'undefined' ? opts.before : before

            haystack = opts.haystack
        }
        haystack = haystack.replace(needle, marker)
        haystack = haystack.indexOf(marker) !== -1 ? haystack : `${marker}${haystack}`
        haystack = haystack.replace(
            marker,
            before ? `${wrapper(thread)}${needle}` : `${needle}${wrapper(thread)}`,
        )

        return haystack
    }
}

class UtilFactory {
    constructor() {
        /// If we already have an instance, return it
        if (singleton) return singleton.instance

        // create a unique, global symbol namespace
        // -----------------------------------
        const globalNamespace = Symbol.for(namespace)

        // check if the global object has this symbol
        // add it if it does not have the symbol, yet
        // ------------------------------------------
        var globalSymbols = Object.getOwnPropertySymbols(global)
        var utilInitialized = globalSymbols.indexOf(globalNamespace) > -1

        /// This should always be unitialized, probably
        if (!utilInitialized) {
            global[globalNamespace] = new util()

            // define the singleton API
            // ------------------------
            singleton = {}

            Object.defineProperty(singleton, 'instance', {
                get: function () {
                    return global[globalNamespace]
                },
            })

            // ensure the API is never changed
            // -------------------------------
            Object.freeze(singleton)
        }

        // export the singleton API only
        // -----------------------------
        return singleton.instance
    }
}

module.exports = UtilFactory
module.exports.namespace = namespace
