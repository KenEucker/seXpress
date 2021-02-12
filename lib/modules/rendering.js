/// Begin with the module name
const moduleName = 'rendering'

/// Name the module init method which is used in logging
function InitRendering(initial, renderingOpts = {}) {
    /// dependencies are scoped to the module itself
    const fs = require('fs')
    const { renderSync } = require('sass')
    const { join } = require('path')
    const { merge, getFunctionName, injectIntoString } = this.middlewares.util

    this.config.rendering = this.getCoreOpts(
        moduleName,
        merge(renderingOpts, {
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
        opts = merge(
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

                renderedString = injectIntoString({
                    haystack: renderedString,
                    needle: '</head>',
                    thread: cssString,
                    wrapper: (css) => `<style type="text/css" nonce="{{nonce}}">${css}</style>`,
                })
            }

            if (this.config.debug && targetFileIsIndex) {
                this.log.debug(`Injecting dev reload script into rendered output`)
                renderedString = injectIntoString({
                    haystack: renderedString,
                    needle: '</body>',
                    thread: `<!-- Dev --><script src="/reload/reload.js" type="text/javascript" nonce="{{nonce}}"></script><!-- Dev -->`,
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
        let overrideRenderer = renderer
            ? typeof renderer === 'function'
                ? getFunctionName(renderer)
                : renderer
            : this.config.rendering.overrideViewEngine

        const setOverrideViewEngine = (rendererToUse, renderer, stylerToUse) => {
            stylerToUse = stylerToUse ? stylerToUse : this.config.rendering.overrideStyleEngine
            let sexyRenderFunction

            switch (rendererToUse) {
                case 'liquid':
                    const { Liquid } = require('liquidjs')
                    const liquidOpts = merge(
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
                                    `<script type="text/javascript" nonce="${nonce}">console.log(${data})</script>`,
                                stylesheet_tag: (href, nonce, defer) =>
                                    `<link href="${href}" rel="stylesheet" type="text/css" media="all" ${
                                        defer ? 'defer' : ''
                                    } nonce="${nonce}"/>`,
                                javascript_tag: (src, nonce, defer) =>
                                    `<script src="${src}" type="text/javascript" ${
                                        defer ? 'defer' : ''
                                    } nonce="${nonce}"></script>`,
                                img_tag: (src, alt) =>
                                    `<img src="${src}" alt="${alt ? alt : src}">`,
                                meta_name: (name, content) =>
                                    `<meta name="${name}" content="${content}">`,
                                meta_prop: (name, content) =>
                                    `<meta property="${name}" content="${content}">`,
                                asset_url: (asset) => `/public/${asset}`,
                                ie_script: (src, nonce) =>
                                    `<!-- [if lte IE 9]><script src="${src}" nonce="${nonce}"></script><![endif] -->`,
                                ie_style: (src, nonce) =>
                                    `<noscript><!--[if lte IE 9]><link rel="stylesheet" href="${src}" nonce="${nonce}"/><![endif]--></noscript>`,
                                safe_script: (inner, nonce) =>
                                    `<script nonce="${nonce}" type="text/javascript">
										((loaderIsSet) => {
											if (!loaderIsSet) window.sexy = { load: [] }
											else window.sexy.load = window.sexy.load || []
											window.sexy.load.push(()=> {
												${inner}
											})
										})(window.sexy)
									</script>`,
                                safe_style: (inner, nonce) =>
                                    `<style nonce="${nonce}" type="text/css">${inner}</style>`,
                                module_script: (src, nonce) =>
                                    `<script src="${src}" nonce="${nonce}" type="module"></script>`,
                                sexy_app_script: (api = '', nonce) =>
                                    `<script src="/public/js/${
                                        this.config.api.apiFilename
                                    }" type="text/javascript" nonce="${nonce}"></script>
									<script src="/public/js/${this.config.name.replace(
                                        ' ',
                                        '',
                                    )}.js" type="text/javascript" nonce="${nonce}"></script>`,
                                sexy_api_script: (api = '', nonce) =>
                                    `<script src="/public/js/${
                                        this.config.api.apiFilename
                                    }" type="text/javascript" nonce="${nonce}"></script>
                                    ${
                                        api.length
                                            ? `<script src="/public/js/${api}" type="module" nonce="${nonce}"></script>`
                                            : ''
                                    }`,
                                sexy_data: (data, name, nonce) => `
								<script nonce="${nonce}">
								((isSet) => {
									if (!isSet) {
										window.sexy = {}
										window.sexy.data = {}
									}

									try {
										window.sexy.data.${name} = JSON.parse(\`${data}\`)
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

                case 'marko':
                    /// TODO: do this
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
