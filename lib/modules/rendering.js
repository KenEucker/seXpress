/// Begin with the module name
const moduleName = 'rendering'

/// Name the module init method which is used in logging
function InitRendering(initial, renderingOpts = {}) {
    /// dependencies are scoped to the module itself
    const fs = require('fs')
    const { renderSync } = require('sass')
    const { join } = require('path')
    const util = require('../util')(this.config.appRoot)

    this.config.rendering = this.getCoreOpts(
        moduleName,
        util.merge(renderingOpts, {
            renderer: !!this.config.rendering ? this.config.rendering.renderer : undefined,
            enabled: typeof this.config.rendering === 'boolean' ? !!this.config.rendering : true,
        }),
        initial,
    )

    /// Cached response
    const compileStyleAndInjectThenRender = (targetFilePath, templateSassFilePath, opts = {}) => {
        /// Support only passing in the targetFilePath and override opts
        if (typeof templateSassFilePath === 'object') {
            opts = templateSassFilePath
            templateSassFilePath = null
        }
        /// Set the default opts
        opts = util.merge(
            {
                injectionTarget: '</head>',
                before: true,
                rendererExt: 'ejs',
                injectMarker: '%%STYLEINJECTEDHERE%%',
                stylerExt: 'scss',
                templateSassFilePath,
            },
            opts,
        )

		/// TODO: make this more intelligent
		const targetFileIsIndex = targetFilePath.indexOf('index') !== -1
        /// Ensure the correct extension is set, this makes {file}.{ext} out of {file} and of {file}.{ext}
        targetFilePath = `${targetFilePath.replace(`.${opts.rendererExt}`, '')}.${opts.rendererExt}`

        /// If the templateSassFilePath is not set, set it to be the same as the targetFilePath only with the overrideStyle extension
        templateSassFilePath = templateSassFilePath
            ? templateSassFilePath
            : targetFilePath.replace(`.${opts.rendererExt}`, `.${opts.stylerExt}`)

        /// Set the cache key for this specific template
        const cacheKey = opts.cacheKey
            ? opts.cacheKey
            : `${moduleName}::<${targetFilePath.replace(
                  this.config.folders.appFolder,
                  '',
              )}|${templateSassFilePath.replace(this.config.folders.appFolder, '')}>`
        let targetString = this.cache.get(cacheKey)

        if ((!targetString || this.config.debug) && fs.existsSync(targetFilePath)) {
            let renderedString = fs.readFileSync(targetFilePath).toString()

            if (fs.existsSync(templateSassFilePath)) {
                /// TODO: add support for something other than scss?
                const styleRendered = renderSync({ file: templateSassFilePath })
                const cssString = styleRendered.css
                this.log.debug(
                    !cssString
                        ? 'erorr rendering embedded style'
                        : 'styles rendered and embedded into view',
                    {
                        templateSassFilePath,
                    },
                )

                renderedString = util.injectIntoString({
					haystack: renderedString,
					needle: '</head>',
					thread: cssString,
					wrapper: (css) => `<style nonce={{nonce}} type="text/css">${css}</style>`,
				})
			}
			
			if (this.config.debug && targetFileIsIndex) {
				this.log.debug(`Injecting dev reload script into rendered output`)
				renderedString = util.injectIntoString({
					haystack: renderedString,
					needle: '</body>',
					thread: `<!-- Dev --><script src="/reload/reload.js" type="text/javascript"></script><!-- Dev -->`,
				})
			}

            targetString = renderedString
            this.cache.set(cacheKey, targetString)
        } else {
            this.log.debug(`using cached version of this view/template`, cacheKey)
        }

        if (typeof opts.renderer === 'function' && opts.viewData) {
            return opts.renderer(targetString, opts.viewData)
        }

        return targetString
    }

    if (this.config.rendering.enabled) {
        let renderer = this.config.rendering.renderer
        let overrideRenderer = renderer //& typeof renderer !== 'boolean'
            ? typeof renderer === 'function'
                ? util.getFunctionName(renderer)
                : renderer
            : this.config.rendering.overrideViewEngine

        const setOverrideViewEngine = (rendererToUse, renderer, stylerToUse) => {
            stylerToUse = stylerToUse ? stylerToUse : this.config.rendering.overrideStyleEngine
            let sexyRenderFunction

            switch (rendererToUse) {
                case 'liquid':
                    const { Liquid } = require('liquidjs')
                    const liquidOpts = util.merge(
                        {
                            dynamicPartials: true,
                            strict_filters: true,
                            extname: '.liquid',
                            root: [
                                '_includes',
                                join(this.config.folders.templatesFolder, 'base'),
                                this.config.folders.viewsFolder,
                            ],
                            customFilters: {
                                console_log: (data, nonce) =>
                                    `<script nonce="${nonce}">console.log(${data})</script>`,
                                stylesheet_tag: (href) =>
                                    `<link href="${href}" rel="stylesheet" type="text/css" media="all" />`,
                                javascript_tag: (src) =>
                                    `<script src="${src}" rel="stylesheet" type="text/javascript"></script>`,
                                img_tag: (src, alt) =>
                                    `<img src="${src}" alt="${alt ? alt : src}">`,
                                meta_name: (name, content) =>
                                    `<meta name="${name}" content="${content}">`,
                                meta_prop: (name, content) =>
                                    `<meta property="${name}" content="${content}">`,
                                asset_url: (asset) => `/public/${asset}`,
                                ie_script: (src) =>
                                    `<!-- [if lte IE 9]><script src="${src}"></script><![endif] -->`,
                                ie_style: (src) =>
                                    `<noscript><!--[if lte IE 9]><link rel="stylesheet" href="${src}" /><![endif]--></noscript>`,
                                safe_script: (inner, nonce) =>
                                    `<script nonce="${nonce}" type="text/javascript">${inner}</script>`,
                                safe_style: (inner, nonce) =>
                                    `<style nonce="${nonce}" type="text/css">${inner}</style>`,
                                sexy_api_script: (nonce) =>
                                    `<script src="/public/js/${this.config.api.apiFilename}" type="text/javascript"></script>`,
                                sexy_data: (name, nonce) => `
								<script nonce="${nonce}"t>
								((isSet) => {
									if (!isSet) {
										window.sexy = {}
										window.sexy.data = {}
									}

									try {
										window.sexy.data[${name}] = JSON.parse(\`{{ ${name} | json }}\`)
									} catch(e) {
										console.log('Could not load sexy page data [${name}]', { error: e })
									}
								})(window.sexy)
								</script>`,
                                sexy_hook: (hook, text, classes, target, container) =>
                                    `${
                                        container
                                            ? `<${container}${
                                                  classes ? ` class="${classes}"` : ''
                                              }>`
                                            : ''
                                    }<a href="hooks.host/${hook}" ${
                                        !container && classes ? ` class="${classes}"` : ''
                                    }${target ? `target="${target}"` : ''}>${text}</a>${
                                        container ? `</${container}>` : ''
                                    }`,
                            },
                        },
                        this.config.rendering.liquid || {},
                    )

                    const liquid = new Liquid(liquidOpts)

                    Object.keys(liquidOpts.customFilters).forEach((filter) => {
                        const filterMethod = liquidOpts.customFilters[filter]

                        this.log.debug(`🧬 adding custom liquid filter [${filter}]`)
                        liquid.registerFilter(filter, filterMethod)
                    })

                    sexyRenderFunction = function sexyLiquidRenderer(
                        viewFilePath,
                        viewData,
                        callback,
                    ) {
                        const viewFileString = compileStyleAndInjectThenRender(viewFilePath, {
                            rendererExt: 'liquid',
                        })
                        const viewRendered = liquid.parseAndRenderSync(viewFileString, viewData)

                        return callback(null, viewRendered)
                    }
                    break

                case 'ejs':
                    const ejs = require('ejs')
                    sexyRenderFunction = function sexyEjsRenderer(
                        viewFilePath,
                        viewData,
                        callback,
                    ) {
                        const viewRendered = compileStyleAndInjectThenRender(viewFilePath, {
                            rendererExt: rendererToUse,
                            renderer: ejs.render,
                            viewData,
                        })
                        return callback(null, viewRendered)
                    }
                    break

                default:
                    /// Nothing to see here
                    sexyRenderFunction = renderer
                    break
            }

            /// Create our sexy rendering engine and set it as the overridden engine
            this.app.engine(rendererToUse, sexyRenderFunction.bind(this))

            /// Override the view engine
            this.app.set('view engine', rendererToUse)

            return sexyRenderFunction
        }
        /// convert to array so we can loop through
        overrideRenderer = !(
            typeof overrideRenderer === 'array' || typeof overrideRenderer === 'object'
        )
            ? [overrideRenderer]
            : overrideRenderer
        /// load all of the remaining engines
        let defaultRendererSet = false
        overrideRenderer.forEach((engine) => {
            const rendererOverride = setOverrideViewEngine(engine)
            if (!defaultRendererSet) {
                defaultRendererSet = true
                this.__renderer = rendererOverride
            }
        })

        /// TODO: make this a configurable feature
        this.config.rendering.enabled = true

        /// Set the default application views
        this.app.set('views', this.config.folders.viewsFolder)

        this.log.debug('🎨 supporting rendering of views in the folder', {
            folder: this.config.folders.viewsFolder,
            engines: overrideRenderer,
        })
    }
}

module.exports = InitRendering
module.exports.module = moduleName
module.exports.description = 'Adds basic html and sexy rendering support'
module.exports.defaults = {
    overrideViewEngine: 'ejs',
    overrideStyleEngine: 'scss',
}
module.exports.version = '0.0.1'
