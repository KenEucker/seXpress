const fs = require('fs')
const sass = require('sass')

module.exports = function (renderer) {
    const self = this
    let rendererToUse =
        typeof renderer === 'string'
            ? renderer
            : typeof renderer === 'function'
            ? 'custom'
            : this.config.overrideViewEngine

    switch (rendererToUse) {
        case 'custom':
            /// Nothing to see here
            this.__renderer = renderer
            break

        case 'liquid':
            const { Liquid } = require('liquidjs')
            const liquid = new Liquid({
                dynamicPartials: true,
                strict_filters: true,
                root: ['_includes', this.config.viewsFolder],
            })
            this.__renderer = function sexyRenderer(viewFilePath, viewData, callback) {
                /// Ensure the correct extension is set
                viewFilePath = `${viewFilePath.replace(`.${self.config.overrideViewEngine}`, '')}.${
                    self.config.overrideViewEngine
                }`
                const viewFileString = fs.readFileSync(viewFilePath, 'utf-8')
                // console.log({viewData, page: viewData.page})

                // return ejs.render(viewFilePath, options, (err, viewRendered) => {
                // if (err) return callback(err)
                liquid.parseAndRender(viewFileString, viewData).then((viewRendered) => {
                    let rendered = viewRendered
                    const templateSass = viewFilePath.replace(
                        `.${self.config.overrideViewEngine}`,
                        `.${self.config.styleEngine}`,
                    )

                    if (fs.existsSync(templateSass)) {
                        const styleRendered = sass.renderSync({ file: templateSass })
                        const css = styleRendered.css
                        rendered = (!!css ? `<style>\n${css}\n</style>` + '\n' : '') + rendered
                    }

                    return callback(null, rendered)
                })
            }
            break

        default:
        case 'ejs':
            const ejs = require('ejs')
            this.__renderer = function sexyRenderer(viewFilePath, viewData, callback) {
                /// Ensure the correct extension is set
                viewFilePath = `${viewFilePath.replace(`.${self.config.overrideViewEngine}`, '')}.${
                    self.config.overrideViewEngine
                }`

                return ejs.renderFile(viewFilePath, viewData, (err, viewRendered) => {
                    if (err) return callback(err)

                    let rendered = viewRendered
                    const templateSass = viewFilePath.replace(
                        `.${this.config.overrideViewEngine}`,
                        `.${this.config.styleEngine}`,
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
                        rendered = (!!css ? `<style>\n${css}\n</style>` + '\n' : '') + rendered
                    }

                    return callback(null, rendered)
                })
            }
            break
    }

    this.config.overrideViewEngine = rendererToUse

    /// TODO: make this a configurable feature
    this.config.supportRendering = true

    /// Create our sexy rendering engine and set it as the overridden engine
    this.app.engine(this.config.overrideViewEngine, this.__renderer.bind(this))

    /// Override the view engine
    this.app.set('view engine', this.config.overrideViewEngine)

    /// Set the default application views
    this.app.set('views', this.config.viewsFolder)

    this.log.debug('supporting rendering of views in the folder', {
        folder: this.config.viewsFolder,
        engine: this.app.get('view engine'),
    })
}
module.exports.module = 'rendering'
module.exports.description = 'Adds basic html and sexy rendering support'
