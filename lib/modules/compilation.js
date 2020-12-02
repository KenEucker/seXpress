/// Begin with the module name
const moduleName = 'compilation'

/// Name the module init method which is used in logging
async function InitCompilation(initial, compilationOpts) {
    this.config.compilation = this.getCoreOpts(moduleName, compilationOpts, initial)
    if (this.config.compilation.enabled) {
        return new Promise(async (resolve, reject) => {
			const {join} = require('path')
			const tsc = require('node-typescript-compiler')
			const compilerOptions = this.config.compilation.compilerOptions
			compilerOptions.outDir = compilerOptions.outDir ? join(this.config.folders.appFolder, compilerOptions.outDir) : this.config.folders.publicFolder
			compilerOptions.rootDir = this.config.folders.appFolder//compilerOptions.outDir ? join(this.config.folders.appFolder, compilerOptions.rootDir) : undefined
			// compilerOptions.rootDirs = compilerOptions.rootDirs ? compilerOptions.rootDirs.map(f => join(compilerOptions.rootDir, f)) : undefined
			compilerOptions.rootDirs = [this.config.folders.publicFolder, join(this.config.folders.appFolder, 'src')]
			const sourceFiles = this.config.compilation.files ? this.config.compilation.files.map(f => join(compilerOptions.rootDir, f)) : []

			this.log.status(`🧿  beginning sourcefile compilation`, {compilerOptions, sourceFiles})
            await tsc.compile(compilerOptions, sourceFiles)

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
        noImplicitAny: false,
        moduleResolution: "node",
		// sourceMap: true,
        esModuleInterop: true,
        // allowSyntheticDefaultImports: true
	},
}
module.exports.version = '0.0.1'
