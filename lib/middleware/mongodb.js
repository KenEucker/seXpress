class MongodbMiddleware {
    constructor(mongodbOpts = {}) {
        this.opts = {}

        if (typeof mongodbOpts === 'boolean') {
            mongodbOpts = {
                /// DO NOT EXPLICITELY RUN THIS CONTAINER
                /// Mongodb must be enabled externally
                /// TODO: detect if docker is installed
                // DO NOT DO THIS -> enabled: mongodbOpts, docker must be installed externally
                mongodbDockerImage: 'mongodb',
            }
        }

        if (mongodbOpts.enabled) {
            if (mongodbOpts.server) {
                console.log({ mongodbOpts })
            } else {
                const { existsSync } = require('fs')
                const { join, resolve } = require('path')
                this.opts = mongodbOpts
                this.opts.log = true

                this.opts.dockerFolder = resolve('./docker/mongodb')
                this.opts.mongodbDockerFile = this.opts.mongodbDockerFile
                    ? this.opts.mongodbDockerFile
                    : join(this.opts.dockerFolder, 'docker-compose.yaml')
                this.opts.mongodbDockerImage = this.opts.mongodbDockerImage
                    ? this.opts.mongodbDockerImage
                    : 'mongodb'
                this.opts.mongodbDockerName = this.opts.mongodbDockerName
                    ? this.opts.mongodbDockerName
                    : this.opts.mongodbDockerImage
                this.opts.mongodbDockerContainerName = this.opts.mongodbDockerContainerName
                    ? this.opts.mongodbDockerContainerName
                    : `${this.opts.mongodbDockerName}_container`
                this.opts.publicPort = this.opts.publicPort ? this.opts.publicPort : 27017 // WP
                this.opts.exposePort = this.opts.exposePort ? this.opts.exposePort : 27017

                if (!existsSync(this.opts.dockerFolder)) {
                    const mkdirp = require('mkdirp')
                    mkdirp.sync(this.opts.dockerFolder)
                }

                this.opts.composeOpts = {
                    cwd: this.opts.dockerFolder,
                    log: this.opts.log,
                    config: this.opts.mongodbDockerFile,
                }
            }
        }
    }

    async init(middlewares) {
        this.compose = require('docker-compose')
        const { writeFileSync, existsSync } = require('fs')

        /// TODO: add the mongodb subdomain and point it to mongodb install

        if (!existsSync(this.opts.mongodbDockerFile)) {
            const { stringify: yamilify } = require('yaml')
            const mongodbDockerYaml = {
                version: '3.3',
                services: {
                    mongo: {
                        image: 'mongo',
                        restart: 'always',
                        ports: [`${this.opts.publicPort + 1}:${this.opts.exposePort + 1}`],
                        environment: {
                            MONGO_INITDB_ROOT_USERNAME: 'root',
                            MONGO_INITDB_ROOT_PASSWORD: 'example',
                        },
                    },
                    'mongo-express': {
                        image: 'mongo-express',
                        restart: 'always',
                        ports: [`8081:8081`],
                        environment: {
                            ME_CONFIG_MONGODB_ADMINUSERNAME: 'root',
                            ME_CONFIG_MONGODB_ADMINPASSWORD: 'example',
                        },
                        depends_on: ['mongo'],
                    },
                },
            }

            console.log('writing new mongodb docker file', this.opts.mongodbDockerFile)
            writeFileSync(this.opts.mongodbDockerFile, yamilify(mongodbDockerYaml))
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

    /// TODO: make this a registerable hook
    async close() {
        if (this.opts.server && !this.opts.persist) {
            console.log('RYING')
            try {
                await this.compose.down(this.opts.composeOpts).then(
                    () => {
                        console.log('mongodb docker container stopped')
                    },
                    (err) => {
                        console.log('could not stop mongodb docker image', {
                            image: this.opts.mongodbDockerImage,
                            err,
                        })
                    },
                )
                console.log('why?')
            } catch (e) {
                console.log({ e })
            }
        }
        return Promise.resolve()
    }
}

module.exports = MongodbMiddleware
