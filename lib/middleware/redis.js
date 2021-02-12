class RedisMiddleware {
    constructor(redisOpts = {}) {
        this.opts = {}

        if (typeof redisOpts === 'boolean') {
            redisOpts = {
                /// Redis must be enabled externally
                // DO NOT DO THIS -> enabled: redisOpts, redis-server must be installed externally
                /// TODO: detect if redis-server is installed
                // enabled: redisServerIsInstalled,
            }
        }

        redisOpts.log = typeof redisOpts.log !== 'undefined' ? redisOpts.log : true
        redisOpts.redisDockerImage = redisOpts.redisDockerImage
            ? redisOpts.redisDockerImage
            : 'redis:alpine'

        if (redisOpts.enabled) {
            if (redisOpts.server) {
                this._client = redisOpts.client
                this._server = redisOpts.server
                this._store = redisOpts.store
                this.opts = redisOpts.opts
                console.log({ redisOpts: this.opts })
            } else {
                this.opts = redisOpts
            }
        }
    }

    async init() {
        const { existsSync, writeFileSync } = require('fs')
        const { join, resolve } = require('path')
        this.compose = require('docker-compose')

        this.opts.dockerFolder = resolve('./docker/redis')
        this.opts.redisDockerFile = this.opts.redisDockerFile
            ? this.opts.redisDockerFile
            : join(this.opts.dockerFolder, 'docker-compose.yaml')
        this.opts.publicPort = this.opts.publicPort ? this.opts.publicPort : 6379
        this.opts.exposePort = this.opts.exposePort ? this.opts.exposePort : 6379
        this.opts.composeOpts = {
            cwd: this.opts.dockerFolder,
            log: this.opts.log,
            config: this.opts.redisDockerFile,
        }
        return

        if (!existsSync(this.opts.dockerFolder)) {
            const mkdirp = require('mkdirp')
            mkdirp.sync(this.opts.dockerFolder)
        }

        if (!existsSync(this.opts.redisDockerFile)) {
            const { stringify: yamilify } = require('yaml')
            const redisDockerYaml = {
                version: '3.2',
                services: {
                    redis: {
                        ports: [`${this.opts.publicPort}:${this.opts.exposePort}`],
                        image: this.opts.redisDockerImage,
                        restart: 'always',
                        command: 'redis-server --requirepass sOmE_sEcUrE_pAsS',
                        environment: {
                            REDIS_REPLICATION_MODE: 'master',
                        },
                        volumes: [
                            '$PWD/redis-data:/var/lib/redis',
                            '$PWD/redis.conf:/usr/local/etc/redis/redis.conf',
                        ],
                    },
                },
            }

            console.log('writing new redis docker file', this.opts.redisDockerFile)
            writeFileSync(this.opts.redisDockerFile, yamilify(redisDockerYaml))
        }

        await this.compose.upAll(this.opts.composeOpts).then(
            () => {
                console.log('redis docker container started')
                this._server = true
            },
            (err) => {
                console.log({ err })
                this._server = false
            },
        )
    }

    client() {
        if (!this._client) {
            const redis = require('async-redis')

            this._client = redis.createClient({ host: this.opts.host })
        }

        return this._client
    }

    server() {
        if (!this._server) {
            const merge = require('deepmerge')
            const RedisServer = require('redis-server')

            const redisServerOpts =
                this.opts ||
                merge(
                    {
                        port: 6379,
                    },
                    redisOpts,
                )

            /// Start our Redis server
            this._server = new RedisServer(redisServerOpts)
            this._opts = redisServerOpts
        }

        return this._server
    }

    store() {
        if (!this._store) {
            const session = require('express-session')
            const connectRedis = require('connect-redis')

            const RedisStore = connectRedis(session)
            const client = this.client()

            this._store = new RedisStore({ client })
        }

        return this._store
    }

    /// TODO: make this a registerable hook
    async close() {
        if (this._client) {
            await this._client.quit()
        }

        if (this._server && this._server.close) {
            await this._server.close()
        }

        if (this._server && !this.opts.persist) {
            try {
                console.log('rying', { composeOpts: this.opts.composeOpts })
                await this.compose.down(this.opts.composeOpts)
                // .then(
                // 	() => {
                // 		console.log('redis docker container stopped')
                // 	},
                // 	(err) => {
                // 		console.log('could not stop redis docker image', {
                // 			image: this.opts.redisDockerImage,
                // 			err,
                // 		})
                // 	},
                // )
                console.log('afteer')
            } catch (e) {
                console.log('hella error', { e })
            }
        }

        return Promise.resolve()
    }
}

module.exports = RedisMiddleware
