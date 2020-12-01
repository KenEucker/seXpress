/// Begin with the module name
const moduleName = 'ssl'

/// Name the module init method which is used in logging
function InitSSL(initial, sslOpts = {}) {
    this.config.ssl = this.getCoreOpts(moduleName, sslOpts, initial)

    if (this.config.ssl.enabled) {
        const https = require('https')
        const enforceSSL = require('express-enforces-ssl-update')
        let configMessage = 'to use certificates on this machine'

        if (!(this.config.debug || this.config.host.indexOf('localhost') !== -1)) {
            const path = require('path')
            const fs = require('fs')
            let serverOpts = {}

            switch (this.config.ssl.strategy) {
				default:
				case 'greenlock':
					this.__ssl = () => {
						const greenlock = require("greenlock-express")
						const serverOpts = {
							packageRoot: this.config.folders.appFolder,
							configDir: this.config.folders.configFolder,
	
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

						this.log.info(
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
						this.log.info(
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
						this.log.info(
							`configuring SSL using certificate strategy [${this.config.ssl.strategy}]`,
							serverOpts,
						)
						return https.createServer(serverOpts, this.app)
					}
                    break
			}
			
            this.config.ssl.opts = serverOpts
        } else {
            this.config.ssl.port = this.config.debug ? this.config.port : this.config.ssl.port
            this.config.port = this.config.debug ? 80 : this.config.port
            configMessage = `to use self-signed certs and httpsLocalHost`

            this.__ssl = async () => {
                const httpsLocalhost = require('https-localhost')()
                const certs = await httpsLocalhost.getCerts()
                this.config.ssl.opts = {
                    certAndKey: certs,
                }

                this.log.debug(`configuring SSL for localhost`, certs)

                return https.createServer(certs, this.app)
            }
        }

        this.config.protocol = 'https'
        this.app.enable('trust proxy')
        this.app.use(enforceSSL({ port: this.config.ssl.port }))

        this.log.info(`🔐 ssl has been configured ${configMessage}`)
    }
}

module.exports = InitSSL
module.exports.module = moduleName
module.exports.description =
    'Allows for the creation and use of ssl certficates and returns an http server'
module.exports.defaults = {
    enabled: false,
	port: 443,
	strategy: 'greenlock',
}
module.exports.version = '0.0.1'
