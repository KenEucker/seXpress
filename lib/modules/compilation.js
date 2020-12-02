/// Begin with the module name
const moduleName = 'compilation'

/// Name the module init method which is used in logging
async function InitCompilation(initial, compilationOpts) {
    this.config.compilation = this.getCoreOpts(moduleName, compilationOpts, initial)
    if (this.config.compilation.enabled) {
        return new Promise(async (resolve, reject) => {
            const tsc = require('node-typescript-compiler')
			
			await tsc.compile(this.config.compilation.compilerOptions, [], { verbose: true })//, this.config.compilation.files)

            resolve()
        })
    }
}

module.exports = InitCompilation
module.exports.module = moduleName
module.exports.description = 'Compiles the src folder into the public folder'
module.exports.defaults = {
	enabled: false,
	compilerOptions: {
	}
}
module.exports.version = '0.0.1'
