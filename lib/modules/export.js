/// Begin with the module name
const moduleName = 'export'

/// Name the module init method which is used in logging
function InitExport(initial, exportOpts = {}) {
    this.config.export = this.getCoreOpts(moduleName, exportOpts, initial)

    // const apiDocsTemplateDestination = path.resolve(this.config.folders.templatesFolder, 'docs')
    /// TODO: send to temporary folder to archive into a .zip file that can be downloaded from the api/docs path alongside the swagger.json
    // const swaggerServerCodegen = require('swagger-node-codegen')
    // const swaggerClientCodegen = require('swagger-codegen')
    /// Generate the clientside code to consume the API
    // const clientsideCode = swaggerClientCodegen({
    // 	swagger: this.getSwaggerSpec(this.config),
    // Templates that run per #/definition
    // perDefinition: {
    //   // Substitute for your own handlebars template
    //   // and generate as many as you want.
    //   './path/to/def-template.hbs': {
    // 	target: './target-folder',
    // 	extension: '.js', // Default
    // 	/* Add your own options for templates here */
    //   }
    // },
    // // Templates that run per grouping of
    // // path attributes
    // perPath: {
    //   // Substitute for your own handlebars template
    //   // and generate as many as you want.
    //   './path/to/def-template.hbs': {
    // 	groupBy: 'x-swagger-router-controller',
    // 	target: './controllers',
    // 	extension: '.js', // Default
    // 	operations: ['get', 'put', 'post', 'delete'], // Default
    // 	/* Add your own options for templates here */
    //   }
    // }
    // 	failureHandler: e => console.error(e),
    //   })
    //   console.log({clientsideCode})
    // swaggerServerCodegen.generate({
    // 	swagger: this.getSwaggerSpec(this.config),
    // 	target_dir: apiDocsTemplateDestination,
    // }).then(() => {
    // 	this.log.info(`API template generated`, apiDocsTemplateDestination)
    // }).catch(err => {
    // 	this.log.error(`API template generation failed: ${err.message}`);
    // })

    /// TODO: this should obviously be more than just the config and some items should be removed
    return this.config
}

module.exports = InitExport
module.exports.module = moduleName
module.exports.description = 'Reduces this sexpress application to a single json object'
module.exports.version = '0.0.1'
