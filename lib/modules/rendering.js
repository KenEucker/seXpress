module.exports = function () {
    /// TODO: make this a configurable feature
    this.config.supportRendering = true

    /// Create our sexy rendering engine and set it as the overridden engine
    this.app.engine(this.config.overrideViewEngine, this.sexyRenderer.bind(this))

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
