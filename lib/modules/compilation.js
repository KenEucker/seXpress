/// Begin with the module name
const moduleName = 'compilation'

const typeScriptCompile = (config) => {
    const defaults = {
        enabled: false,
        compilerOptions: {
            // module: 'system',
            target: 'es5',
            noImplicitAny: false,
            moduleResolution: 'node',
            // outFile: 'js/api.js',
            // strict: true,
            sourceMap: true,
            esModuleInterop: true,
            allowSyntheticDefaultImports: true,
        },
    }
    return new Promise(async (resolve, reject) => {
        const { join } = require('path')
        const { sync: del } = require('delete')
        const { copyFileSync } = require('fs')
        const { compile } = require('node-typescript-compiler')
        const compilerOptions = this.config.compilation.compilerOptions

        /// Set the absolute paths for outDir
        compilerOptions.outDir = compilerOptions.outDir
            ? join(this.config.folders.appFolder, compilerOptions.outDir)
            : this.config.folders.appFolder
        /// Use the appRoot folder so that the public/js folder can be accessible to the src files compilation
        compilerOptions.rootDir = this.config.folders.appFolder

        const sourceFiles = this.config.compilation.files
            ? this.config.compilation.files.map((f) => join(compilerOptions.rootDir, f))
            : []

        // compilerOptions.outFile = join(
        //     this.config.folders.publicFolder,
        //     compilerOptions.outFile,
        // )

        this.log.status(`🧿  beginning sourcefile compilation`, {
            compilerOptions,
            sourceFiles,
        })
        await compile(compilerOptions, sourceFiles)

        /// Cleanup
        if (this.config.compilation.overwritePublicApi) {
            const existinApiFile = join(
                this.config.folders.publicFolder,
                'js',
                this.config.api.apiFilename,
            )

            /// Overwrite existing api file
            copyFileSync(compilerOptions.outFile, existinApiFile)

            /// Delete the old file
            del([compilerOptions.outFile])

            this.log.debug(
                moduleName,
                `Overwriting pre-compiled application API with compiled src`,
                compilerOptions.outFile,
            )
        }

        resolve()
    })
}

/// Name the module init method which is used in logging
async function InitCompilation(initial, compilationOpts) {
    this.config.compilation = this.getCoreOpts(moduleName, compilationOpts, initial)
    if (this.config.compilation.enabled) {
        return new Promise(async (resolve, reject) => {
            const { join } = require('path')
            const { merge } = this.middlewares.util
            // const { sync: del } = require('delete')
            const { copyFileSync } = require('fs')
            const webpack = require('webpack')
            const library = `${this.config.name.replace(' ', '')}`
            const compilerOptions = merge(
                {
                    mode: this.config.debug ? 'development' : 'production',
                    stats: this.config.debug ? 'verbose' : 'errors-only',
                    watch: !!this.config.debug,
                    output: {
                        library,
                        libraryTarget: 'umd',
                        scriptType: 'module',
                        uniqueName: this.config.name,
                        filename: `${library}.js`,
                        path: `${this.config.folders.publicFolder}/js`,
                        publicPath: this.config.folders.publicFolder,
                        auxiliaryComment: {
                            root: 'Root Comment',
                            commonjs: 'CommonJS Comment',
                            commonjs2: 'CommonJS2 Comment',
                            amd: 'AMD Comment',
                        },
                    },
                },
                this.config.compilation.compilerOptions,
            )
            if (typeof compilerOptions.entry === 'string') {
                compilerOptions.entry = join(this.config.folders.srcFolder, compilerOptions.entry)
            }

            this.config.compilation.opts = compilerOptions
            this.log.status(`🧿  beginning sourcefile compilation`, compilerOptions)
            webpack(compilerOptions, resolve)
        })
    }
}

module.exports = InitCompilation
module.exports.module = moduleName
module.exports.description = 'Compiles the src folder into the public folder'
module.exports.defaults = {
    enabled: false,
    compilerOptions: {
        entry: 'main.coffee',
        module: {
            rules: [
                {
                    test: /\.coffee$/,
                    loader: 'coffee-loader',
                    options: {
                        transpile: {
                            presets: ['@babel/env'],
                        },
                    },
                },
            ],
        },
        resolve: {
            extensions: ['.coffee', '.js'],
        },
    },
}
module.exports.version = '0.0.1'
