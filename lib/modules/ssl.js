/// Begin with the module name
const moduleName = 'ssl'

/// Name the module init method which is used in logging
function InitSSL(initial, sslOpts = {}) {
    this.config.ssl = this.getCoreOpts(moduleName, sslOpts, initial)

    if (this.config.ssl.enabled) {
        const https = require('https')
        const enforceSSL = require('express-enforces-ssl-update')
        let configMessage = 'to use certificates on this machine'

        if (!this.config.ssl.sites || this.config.ssl.sites.length === 0) {
            const altnames = [this.config.host]
            Object.keys(this.config.subdomains).forEach((subdomain) => {
                if (subdomain !== 'index') {
                    altnames.push(`${subdomain}.${this.config.host}`)
                }

                const subdomainAliases = this.config.subdomains[subdomain].aliases || []

                if (subdomainAliases.length) {
                    subdomainAliases.forEach((alias) => {
                        altnames.push(`${alias}.${this.config.host}`)
                    })
                }
            })

            Object.keys(this.coreSubdomains).forEach((index) => {
                const subdomain = this.coreSubdomains[index]
                altnames.push(`${subdomain}.${this.config.host}`)
            })
            this.config.ssl.sites = [{ subject: this.config.host, altnames }]
        }

        const path = require('path')
        const fs = require('fs')
        const mkdirp = require('mkdirp')
        let serverOpts = {}
        this.config.ssl.strategy =
            this.config.host === 'localhost' ? 'localhost' : this.config.ssl.strategy

        switch (this.config.ssl.strategy) {
            case 'localhost':
                /// This creates an error, let's swallow it.
                // this.config.ssl.port = this.config.debug ? this.getPort() : this.config.ssl.port
                configMessage = `to use self-signed certs and httpsLocalHost`

                this.__ssl = async () => {
                    const httpsLocalhost = require('https-localhost')()
                    const certs = await httpsLocalhost.getCerts()
                    this.config.ssl.opts = {
                        certAndKey: certs,
                    }

                    this.log.status(`configuring SSL for localhost`, certs)

                    return https.createServer(certs, this.app)
                }
                break

            case 'greenlock':
                const configDir = path.join(this.config.folders.configFolder, 'greenlock.d')
                if (!fs.existsSync(configDir)) {
                    mkdirp.sync(configDir)
                    const configFile = path.join(configDir, 'config.json')
                    this.log.status(
                        `creating greenlock.d config folder and autopopulating ssl config`,
                        { sites: this.config.ssl, configFile },
                    )

                    fs.writeFileSync(configFile, JSON.stringify(this.config.ssl))
                }

                this.__ssl = () => {
                    const greenlock = require('greenlock-express')
                    const serverOpts = {
                        packageRoot: this.config.folders.appFolder,
                        configDir,

                        // Staging for testing environments
                        staging: this.config.debug,

                        // contact for security and critical bug notices
                        maintainerEmail: this.config.author.email,

                        // whether or not to run at cloudscale
                        cluster: false,

                        // for an RFC 8555 / RFC 7231 ACME client user agent
                        packageAgent: `${this.config.name}/${this.config.version}`,
                    }

                    this.config.ssl.opts = serverOpts
                    greenlock.init(serverOpts).serve(this.app)

                    this.log.status(
                        `configuring SSL using certificate strategy [${this.config.ssl.strategy}]`,
                        serverOpts,
                    )

                    return false
                }
                break

            case 'letsencrypt':
                const certDir = '/etc/letsencrypt/live'
                if (fs.existsSync(certDir)) {
                    const certDirectoryFiles = fs.readdirSync(certDir)
                    const certficates = []

                    certDirectoryFiles.forEach((domain) => {
                        const domainPath = path.join(certDir, domain)
                        const isDirectory = fs.lstatSync(domainPath).isDirectory()

                        if (isDirectory) {
                            certficates[domain] = {}

                            certficates[domain].key = fs.readFileSync(
                                path.join(certDir, domain, 'privkey.pem'),
                            )
                            certficates[domain].cert = fs.readFileSync(
                                path.join(certDir, domain, 'fullchain.pem'),
                            )
                        }
                    })

                    /// TODO: Change this to use as many certs for as many servers as needed
                    serverOpts = {
                        /// TODO: change this from using the passphrase to domain
                        cert: certficates[this.config.ssl.passphrase].cert,
                        key: certficates[this.config.ssl.passphrase].key,
                    }
                }

                this.__ssl = () => {
                    this.log.status(
                        `configuring SSL using certificate strategy [${this.config.ssl.strategy}]`,
                        serverOpts,
                    )
                    return https.createServer(serverOpts, this.app)
                }
                break

            case 'file':
                serverOpts = {
                    cert: fs.readFileSync(this.config.ssl.certificateFilename, 'utf-8'),
                    key: fs.readFileSync(this.config.ssl.certificateKeyFilename, 'utf-8'),
                    // ca: fs.readFileSync(this.config.ssl.certificateAuthorityFilename, 'utf-8'),
                    passphrase: this.config.ssl.passphrase,
                }

                this.__ssl = () => {
                    this.log.status(
                        `configuring SSL using certificate strategy [${this.config.ssl.strategy}]`,
                        serverOpts,
                    )
                    return https.createServer(serverOpts, this.app)
                }
                break
        }

        this.config.ssl.opts = serverOpts

        this.config.protocol = 'https'
        this.app.enable('trust proxy')
        this.app.use(enforceSSL({ port: this.config.ssl.port }))

        this.log.info(
            `🔐 ssl has been configured with ${this.config.ssl.strategy} ${configMessage}`,
            this.config.ssl,
        )
    }
}

module.exports = InitSSL
module.exports.module = moduleName
module.exports.description =
    'Allows for the creation and use of ssl certficates and returns an http server'
module.exports.defaults = {
    enabled: false,
    port: 443,
    strategy: 'localhost',
}
module.exports.version = '0.0.1'
