class WordpressMiddleware {
    constructor(wordpressOpts = {}) {
        this.opts = {}

        if (typeof wordpressOpts === 'boolean') {
            wordpressOpts = {
                /// DO NOT EXPLICITELY RUN THIS CONTAINER
                /// Wordpress must be enabled externally
                /// TODO: detect if docker is installed
                // DO NOT DO THIS -> enabled: wordpressOpts, docker must be installed externally
                wordpressDockerImage: 'wordpress',
            }
        }

        if (wordpressOpts.enabled) {
            if (wordpressOpts.server) {
                console.log({ wordpressOpts })
            } else {
                const { existsSync } = require('fs')
                const { join, resolve } = require('path')
                this.opts = wordpressOpts
                this.opts.log = true

                this.opts.dockerFolder = resolve('./docker/wordpress')
                this.opts.wordpressDockerFile = this.opts.wordpressDockerFile
                    ? this.opts.wordpressDockerFile
                    : join(this.opts.dockerFolder, 'docker-compose.yaml')
                this.opts.wordpressDockerImage = this.opts.wordpressDockerImage
                    ? this.opts.wordpressDockerImage
                    : 'wordpress'
                this.opts.wordpressDockerName = this.opts.wordpressDockerName
                    ? this.opts.wordpressDockerName
                    : this.opts.wordpressDockerImage
                this.opts.wordpressDockerContainerName = this.opts.wordpressDockerContainerName
                    ? this.opts.wordpressDockerContainerName
                    : `${this.opts.wordpressDockerName}_container`
                this.opts.publicPort = this.opts.publicPort ? this.opts.publicPort : 3216 // WP
                this.opts.exposePort = this.opts.exposePort ? this.opts.exposePort : 80

                if (!existsSync(this.opts.dockerFolder)) {
                    const mkdirp = require('mkdirp')
                    mkdirp.sync(this.opts.dockerFolder)
                }

                this.opts.composeOpts = {
                    cwd: this.opts.dockerFolder,
                    log: this.opts.log,
                    config: this.opts.wordpressDockerFile,
                }
            }
        }
    }

    async init(middlewares) {
        this.compose = require('docker-compose')
        const { writeFileSync, existsSync } = require('fs')

        /// TODO: add the wordpress subdomain and point it to wordpress install

        if (!existsSync(this.opts.wordpressDockerFile)) {
            const { stringify: yamilify } = require('yaml')
            const wordpressDockerYaml = {
                version: '3.3',
                services: {
                    db: {
                        image: 'mysql:5.7',
                        restart: 'always',
                        environment: {
                            MYSQL_DATABASE: 'exampledb',
                            MYSQL_USER: 'exampleuser',
                            MYSQL_PASSWORD: 'examplepass',
                            MYSQL_RANDOM_ROOT_PASSWORD: '1',
                        },
                        volumes: ['db_data:/var/lib/mysql'],
                    },
                    wordpress: {
                        depends_on: ['db'],
                        image: 'wordpress:latest',
                        restart: 'always',
                        ports: [`${this.opts.publicPort}:${this.opts.exposePort}`],
                        environment: {
                            WORDPRESS_DB_HOST: 'db',
                            WORDPRESS_DB_USER: 'exampleuser',
                            WORDPRESS_DB_PASSWORD: 'examplepass',
                            WORDPRESS_DB_NAME: 'exampledb',
                        },
                        volumes: ['wordpress:/var/www/html'],
                    },
                },
                volumes: {
                    wordpress: {},
                    db_data: {},
                },
            }

            console.log('writing new wordpress docker file', this.opts.wordpressDockerFile)
            writeFileSync(this.opts.wordpressDockerFile, yamilify(wordpressDockerYaml))
        }

        await this.compose.upAll(this.opts.composeOpts).then(
            () => {
                this.opts.server = true
            },
            (err) => {
                this.opts.server = false
            },
        )
    }

    async restart(opts) {
        return this.compose.restartAll(this.opts.composeOpts)
    }

    async cli(command, opts = {}) {
        return this.compose.exec('node', `wp-cli ${command}`, this.opts.composeOpts)
    }

    /// TODO: make this a registerable hook
    async close() {
        return new Promise(async (resolve, reject) => {
            if (this.opts.server && !this.opts.persist) {
                console.log('RYING wordpress')
                try {
                    await this.compose.down(this.opts.composeOpts)
                    console.log('fi')
                    resolve()
                } catch (e) {
                    console.log({ e })
                }
            }
        })
    }
}

module.exports = WordpressMiddleware
