const chalk = require('chalk')
const cliProgress = require('cli-progress')
const ora = require('ora')
const merge = require('deepmerge')
const logger = require("morgan")
const path = require("path")
let appRoot = require("app-root-path")

// const logger = (message, obj) => {
// 	if (!!obj) {
// 		console.log(message, obj)
// 	} else {
// 		console.log(message)
// 	}
// }

/// appRoot.setPath is used in clobfig
// appRoot.setPath(process.cwd())

const log = ((_logger) => {
	const error = (message, obj = null) => _logger(chalk.red(message), obj)
	const info = (message, obj = null) => _logger(chalk.blueBright(message), obj)
	const log = (message, obj = null) => {
		if (obj) _logger(message, obj)
		else _logger(message)
	}
	const prompt = (message, obj = null) => _logger(chalk.yellow(message), obj)
	const status = (message, obj = null) => _logger(chalk.cyan(message), obj)
	const success = (message, obj = null) => _logger(chalk.green(message), obj)

	const _log = log
	_log.error = error
	_log.info = info
	_log.prompt = prompt
	_log.status = status
	_log.log = log
	_log.success = success

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

const createProgressBar = (length, startValue = 0, autoStart = true, preset = cliProgress.Presets.shades_classic) => {
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
	return new Promise(resolve => task(resolve))
}

const getRootPath = (paths) => {
	if (!Array.isArray(paths)) {
		paths = [paths]
	}

	return appRoot.resolve(path.join(...paths))
}

module.exports = (AppRoot = require('app-root-path')) => {
	appRoot = AppRoot

	return {
		createProgressBar,
		createSpinner,
		log,
		logger,
		getRootPath,
		merge,
		promiseMe,
		stringIsExactMatch,
	}
}
