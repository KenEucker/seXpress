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

        if (this._server) {
            return this._server.close()
        }

        return Promise.resolve()
    }
}

module.exports = RedisMiddleware
