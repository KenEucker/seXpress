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

const createProgressBar = (
    length,
    startValue = 0,
    autoStart = true,
    preset = cliProgress.Presets.shades_classic,
) => {
    const progressBar = new cliProgress.SingleBar({}, preset)
    if (!!autoStart) {
        progressBar.start(length, startValue)
    }
    progressBar._stop = progressBar.stop
    progressBar.stop = function (newLength) {
        this.update(newLength || length)
        this._stop()
    }

    return progressBar
}

const createSpinner = (text = 'processing', preText, autoStart = true) => {
    const spinner = ora(text)
    if (!!preText) {
        spinner.preText = preText
    }
    if (!!autoStart) {
        spinner.start()
    }

    return spinner
}

const promiseMe = (task = () => {}) => {
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

const getSubdomainPrefix = (opts, req, returnAlias = false) => {
    const indexSubdomain = req.subdomains.length ? req.subdomains[0] : opts.indexControllerName
    const localhostSubdomainEnd = !!req.headers.host ? req.headers.host.indexOf('.') : -1
    const localhostOverride =
        localhostSubdomainEnd !== -1 ? req.headers.host.substr(0, localhostSubdomainEnd) : null
    const alias = !!localhostOverride ? localhostOverride : indexSubdomain

    return returnAlias ? alias : getSubdomainFromAlias(opts, alias)
}

const getControllerNameFromFilePath = (controllerFilePath) => {
    const fileNameOmitted = controllerFilePath.replace('/index.js', '')

    return fileNameOmitted.substring(fileNameOmitted.lastIndexOf('/') + 1)
}

const getViews = (opts, viewsFolder) => {
    const out = {}
    viewsFolder = viewsFolder || opts.viewsFolder

    fs.readdirSync(viewsFolder).forEach((filename) => {
        if (path.extname(filename) !== `.${opts.overrideViewEngine}`) return

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
        controllersFiles.sort((a, b) => (a === indexjs ? 1 : b === indexjs ? -1 : 0))

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

const getHostUri = (opts, host, protocol = '') => {
    const fullHost =
        host.indexOf(':') !== -1 ? host : `${host}${opts.port !== 80 ? `:${opts.port}` : ''}`
    return `${protocol ? `${protocol}://` : ''}${fullHost}/api`
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

const getServers = (opts, host, protocol, subdomain, forceSecure = false) => {
    const servers = []

    if (subdomain !== opts.indexControllerName) {
        servers.push({
            url: getHostUri(opts, host, protocol),
        })
    } else {
        Object.keys(opts.subdomains).forEach((subdomain) => {
            const sub = subdomain === opts.indexControllerName ? '' : `${subdomain}.`

            servers.push({
                url: getHostUri(opts, `${sub}${host}`, forceSecure ? 'https' : protocol),
            })
        })
    }

    return servers
}

module.exports = (AppRoot = require('app-root-path')) => {
    appRoot = AppRoot

    return {
        createProgressBar,
        createSpinner,
        log,
        logger,
        mkdirp,
        getControllerNameFromFilePath,
        getControllers,
        getFunctionName,
        getHostUri,
        getRootPath,
        getServers,
        getSubdomainPrefix,
        getValuesFromObjectOrDefault,
        getViews,
        merge,
        promiseMe,
        stringIsExactMatch,
        setInterval,
    }
}
