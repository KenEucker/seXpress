const fs = require('fs')
const path = require('path')
const sass = require('sass')
const util = require('../util')()

const moduleName = 'rendering'

module.exports = function (renderingOpts = {}) {
    this.config.rendering = this.getCoreOpts(moduleName, renderingOpts, {
        renderer: !!this.config.rendering ? this.config.rendering.renderer : undefined,
        overrideViewEngine: 'ejs',
        overrideStyleEngine: 'scss',
        enabled: typeof this.config.rendering === 'boolean' ? !!this.config.rendering : true,
    })

    if (this.config.rendering.enabled) {
        let renderer = this.config.rendering.renderer
        let defaultRenderer = renderer
            ? typeof renderer === 'function'
                ? util.getFunctionName(renderer)
                : renderer
            : this.config.rendering.overrideViewEngine

        const overrideViewEngine = (rendererToUse, renderer, stylerToUse) => {
            stylerToUse = stylerToUse || this.config.rendering.overrideStyleEngine
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
                                path.join(this.config.folders.templatesFolder, 'base'),
                                this.config.folders.viewsFolder,
                            ],
                            customFilters: {
                                stylesheet_tag: (href) =>
                                    `<link href="${href}" rel="stylesheet" type="text/css" media="all" />`,
                                javascript_tag: (src) =>
                                    `<script src="${src}" rel="stylesheet" type="text/javascript"></script>`,
                                img_tag: (src, alt) =>
                                    `<img src="${src}" alt="${alt ? alt : src}">`,
                                meta_tag: (name, content) =>
                                    `<meta name="${name}" content="${content}">`,
                                asset_url: (s) => `/public/${s}`,
                            },
                        },
                        this.config.rendering.liquid || {},
                    )

                    const liquid = new Liquid(liquidOpts)

                    Object.keys(liquidOpts.customFilters).forEach((filter) => {
                        const filterMethod = liquidOpts.customFilters[filter]

                        this.log.debug('adding custom liquid filter', { filter, filterMethod })
                        liquid.registerFilter(filter, filterMethod)
                    })

                    sexyRenderFunction = function sexyLiquidRenderer(
                        viewFilePath,
                        viewData,
                        callback,
                    ) {
                        /// Ensure the correct extension is set
                        viewFilePath = `${viewFilePath.replace(
                            `.${rendererToUse}`,
                            '',
                        )}.${rendererToUse}`
                        const viewFileString = fs.readFileSync(viewFilePath, 'utf-8')

                        liquid.parseAndRender(viewFileString, viewData).then((viewRendered) => {
                            let rendered = viewRendered
                            const templateSass = viewFilePath.replace(
                                `.${rendererToUse}`,
                                `.${stylerToUse}`,
                            )

                            if (fs.existsSync(templateSass)) {
                                const styleRendered = sass.renderSync({ file: templateSass })
                                const css = styleRendered.css
                                rendered =
                                    (!!css ? `<style>\n${css}\n</style>` + '\n' : '') + rendered
                            }

                            return callback(null, rendered)
                        })
                    }
                    break

                case 'ejs':
                    const ejs = require('ejs')
                    sexyRenderFunction = function sexyEjsRenderer(
                        viewFilePath,
                        viewData,
                        callback,
                    ) {
                        /// Ensure the correct extension is set
                        viewFilePath = `${viewFilePath.replace(
                            `.${rendererToUse}`,
                            '',
                        )}.${rendererToUse}`

                        return ejs.renderFile(viewFilePath, viewData, (err, viewRendered) => {
                            if (err) return callback(err)

                            let rendered = viewRendered
                            const templateSass = viewFilePath.replace(
                                `.${rendererToUse}`,
                                `.${stylerToUse}`,
                            )

                            if (fs.existsSync(templateSass)) {
                                const styleRendered = sass.renderSync({ file: templateSass })
                                const css = styleRendered.css
                                this.log.debug(
                                    err
                                        ? 'erorr rendering embedded style'
                                        : 'styles rendered and embedded into view',
                                    {
                                        templateFilePath: viewFilePath,
                                        templateSass,
                                        err,
                                    },
                                )
                                rendered =
                                    (!!css ? `<style>\n${css}\n</style>` + '\n' : '') + rendered
                            }

                            return callback(null, rendered)
                        })
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

        if (typeof defaultRenderer === 'array' || typeof defaultRenderer === 'object') {
            /// use the first in the list as the default engine to set for the app
            const trueDefault = defaultRenderer.shift()

            /// load all of the remaining engines
            defaultRenderer.forEach(overrideViewEngine)

            /// load and set the renderer to the default
            defaultRenderer = trueDefault
            renderer = overrideViewEngine(trueDefault, renderer)
        } else {
            /// load and set the renderer to the default
            renderer = overrideViewEngine(defaultRenderer, renderer)
        }

        /// TODO: make this a configurable feature
        this.config.rendering.enabled = true

        /// Set the default application views
        this.app.set('views', this.config.folders.viewsFolder)

        this.log.debug('supporting rendering of views in the folder', {
            folder: this.config.folders.viewsFolder,
            engine: this.app.get('view engine'),
        })
    }
}

module.exports.module = moduleName
module.exports.description = 'Adds basic html and sexy rendering support'
