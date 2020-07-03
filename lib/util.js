const chalk = require('chalk')
const cliProgress = require('cli-progress')
const ora = require('ora')
const merge = require('deepmerge')
const appRoot = require('app-root-path')
const logger = require("morgan")
const path = require("path")
const _logger = console.log

// const logger = (message, obj) => {
// 	if (!!obj) {
// 		console.log(message, obj)
// 	} else {
// 		console.log(message)
// 	}
// }
appRoot.setPath(process.cwd())

const _log = {
	error: (message, obj) => {
		_logger(chalk.red(message), obj)
	},
	info: (message, obj) => {
		_logger(chalk.blueBright(message), obj)
	},
	log: (message, obj) => {
		_logger((message), obj)
	},
	prompt: (message, obj) => {
		_logger(chalk.yellow(message), obj)
	},
	status: (message, obj) => {
		_logger(chalk.cyan(message), obj)
	},
	success: (message, obj) => {
		_logger(chalk.green(message), obj)
	},
}

const log = _logger
Object.keys(_log).forEach((method) => {
	log[method] = _log[method]
})

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

module.exports = {
	createProgressBar,
	createSpinner,
	log: _log,
	logger,
	getRootPath,
	merge,
	promiseMe,
	stringIsExactMatch,
}
