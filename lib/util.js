const chalk = require('chalk')
const cliProgress = require('cli-progress')
const ora = require('ora')
const fs = require('fs')
const merge = require('deepmerge')
const logger = require('morgan')
const path = require('path')
const mkdirp = require('mkdirp')
const { setInterval } = require('safe-timers')
let appRoot = require('app-root-path')

const log = ((_logger) => {
    _logger.error = _logger.error || _logger

    const error = (message, obj = '') => _logger.error(chalk.red(message), obj)
    const info = (message, obj = '') => _logger(chalk.blueBright(message), obj)
    const log = (message, obj = '') => {
        if (obj) _logger(message, obj)
        else _logger(message)
    }
    const prompt = (message, obj = '') => _logger(chalk.yellow(message), obj)
    const status = (message, obj = '') => _logger(chalk.cyan(message), obj)
    const success = (message, obj = '') => _logger(chalk.green(message), obj)
    const debug = (message, obj = '') => _logger(chalk.blueBright(message), obj)

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
})(console.log)

const stringIsExactMatch = (string1, string2, caseSensitive = true) => {
    const opts = {}

    // negating the default here because it makes the function call look nmore accurate
    if (!caseSensitive) {
        opts.sensitivity = 'base'
    }

    return string1.localeCompare(string2, undefined, opts) === 0
}

const promiseMe = (task) => {
    if (!task) return Promise.resolve()

    return new Promise((resolve) => task(resolve))
}

const getRootPath = (paths) => {
    if (!Array.isArray(paths)) {
        paths = [paths]
    }

    return appRoot.resolve(path.join(...paths))
}

const getValuesFromObjectOrDefault = (
    names,
    input = {},
    defaults = {},
    final = {},
    defaultsOverride = false,
) => {
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

const getSubdomainFromAlias = (opts, alias) => {
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

const getSubdomainPrefix = (opts, req, returnAlias = false) => {
    const hostname = typeof req === 'string' ? req : req.hostname
    const subdomains = hostname
        .replace(/https?:\/\//gi, '')
        .split('.')
        .reverse()
    const isLocalhost = subdomains[0] === 'localhost'
    const offset = isLocalhost ? 0 : 1

    let baseSubdomain = subdomains.length > offset + 1 ? subdomains[offset + 1] : subdomains[offset]

    baseSubdomain =
        opts.host.indexOf(baseSubdomain) === -1 ? baseSubdomain : opts.routing.indexControllerName

    return returnAlias ? baseSubdomain : getSubdomainFromAlias(opts, baseSubdomain)
}

const getControllerNameFromFilePath = (controllerFilePath) => {
    const fileNameOmitted = controllerFilePath.replace('/index.js', '')

    return fileNameOmitted.substring(fileNameOmitted.lastIndexOf('/') + 1)
}

const getViews = (opts, viewsFolder) => {
    const out = {}
    viewsFolder = viewsFolder || opts.folders.viewsFolder

    fs.readdirSync(viewsFolder).forEach((filename) => {
        if (path.extname(filename) !== `.${opts.rendering.overrideViewEngine}`) return

        const viewName = filename.replace(path.extname(filename), '')
        out[viewName] = filename
    })

    return out
}

const getControllers = (opts, controllersFolder, ignore) => {
    controllersFolder = controllersFolder ? controllersFolder : opts.controllersFolder
    const indexjs = 'index.js'
    const out = []

    const _getControllers = (folder, importAll) => {
        /// Run index.js in this folder first before anything else
        const controllersFiles = fs.readdirSync(folder)
        controllersFiles.sort((a, b) => (a === indexjs ? -1 : b === indexjs ? 1 : 0))

        controllersFiles.forEach((filename) => {
            const file = path.join(folder, filename)
            const controllerName = getControllerNameFromFilePath(folder)

            /// Import all folders under this folder
            if (fs.statSync(file).isDirectory()) {
                if (filename !== 'views' && importAll) _getControllers(path.join(folder, filename))
                return
            }

            /// Import only index.js files
            if (filename.indexOf(indexjs) === -1) return
            if (ignore && ignore.indexOf(controllerName) !== -1) return

            out.push(path.join(folder, filename))
        })
    }

    if (fs.existsSync(controllersFolder)) {
        _getControllers(controllersFolder, true)
    }

    return out
}

/// Returns the constructed base URL of the website
const getHostBaseUrl = (opts, host, protocol = '', subdomain, fullHost = true) => {
	if (typeof host === 'boolean' && protocol === '') {
		fullHost = host
		host = opts.host
	}

	host = !!host ? host : opts.host
    let hostname = host,
        baseUrl = host

    const portPresent = hostname.indexOf(':')
    if (portPresent === -1) {
        hostname = `${host}${opts.port !== 80 ? `:${opts.port}` : ''}`
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
const getHostUri = (opts, host, protocol = '', append = '/api', fullHost = true) => {
    return `${getHostBaseUrl(opts, host, protocol, undefined, fullHost)}${append}`
}

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

const isPromise = (mightBeAPromise) => {
    /// TODO: detect a promise better you noob
    return !!mightBeAPromise //&& (typeof mightBeAPromise).toLocaleLowerCase() === 'promise'
}

const extractEmails = (text) => {
    return text.match(/([a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9_-]+)/gi)
}

const consoleLogEmoji = (emoji) => {
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

const consoleLogEmojiNumber = (number) => {
    const numberString = number.toString()
    let out = ''
    for (let i = 0; i < numberString.length; ++i) {
        out += consoleLogEmoji(numberString[i])
    }
    return out
}

const getServers = (
    opts,
    host,
    protocol,
    subdomain,
    forceSecure = false,
    ignoreSubdomains = [],
    isAuthenticated = false,
) => {
    const servers = []
    protocol = forceSecure ? 'https' : protocol
    ignoreSubdomains = typeof ignoreSubdomains === 'string' ? [ignoreSubdomains] : ignoreSubdomains
    ignoreSubdomains.push(opts.routing.indexControllerName)
    const externalServerDescription = `External ${opts.name} application URI`
    const internalServerDescription = `Internal ${opts.name} application URI`

    /// Add the index {host}/api server first, if access is granted
    if (!opts.api.secureApiDocs || isAuthenticated) {
        servers.push({
            url: `${getHostBaseUrl(opts, opts.host, protocol, '')}/api`,
            description: internalServerDescription,
        })
    }

    if (subdomain === 'api' || subdomain == opts.routing.indexControllerName) {
        // if (subdomain !== 'api') {
        // 	servers.push({
        // 		url: getHostBaseUrl(opts, opts.host, protocol, 'api'),
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

            const url = getHostUri(opts, `${apiSubPrefix}${apiHost}`, protocol, `/${sub}`, true)

            servers.push({
                url,
                description,
            })
        })
    }

    return servers
}

const findViewFile = (opts, view, engine) => {
    let foundView = false

    engine = typeof engine === 'undefined' ? opts.rendering.overrideViewEngine : engine
    if (typeof engine === 'array' || typeof engine === 'object') {
        for (const e of engine) {
            if ((foundView = findViewFile(opts, view, e))) break
        }

        return foundView
    }

    const viewFile = path.join(opts.folders.viewsFolder, `${view}.${engine}`)

    if (fs.existsSync(viewFile)) return viewFile

    const viewFileIndex = path.join(opts.folders.viewsFolder, `${view}/index.${engine}`)

    if (fs.existsSync(viewFileIndex)) return viewFileIndex

    return foundView
}

const findTemplateFile = (opts, engine) => {
    const viewFile = path.join(opts.folders.templatesFolder, `${view}.${engine}`)

    if (fs.existsSync(viewFile)) return viewFile

    const viewFileIndex = path.join(opts.folders.viewsFolder, `${view}/index.${engine}`)

    if (fs.existsSync(viewFileIndex)) return viewFileIndex

    return false
}

const injectIntoString = (
    haystack,
    needle,
    thread,
    marker = '%%MARKER%%',
    wrapper = (s) => s,
    before = true,
) => {
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

module.exports = (AppRoot = require('app-root-path')) => {
    appRoot = AppRoot

    return {
        consoleLogEmoji,
        consoleLogEmojiNumber,
        log,
        logger,
        mkdirp,
        extractEmails,
        findTemplateFile,
        findViewFile,
        getControllerNameFromFilePath,
        getControllers,
        getFunctionName,
        getHostBaseUrl,
        getHostUri,
        getRootPath,
        getServers,
        getSubdomainPrefix,
        getValuesFromObjectOrDefault,
        getViews,
        injectIntoString,
        isPromise,
        merge,
        promiseMe,
        stringIsExactMatch,
        setInterval,
    }
}
