class RedisMiddleware {
    constructor(redisOpts = {}) {
        if (typeof redisOpts === 'boolean') {
            redisOpts = {
                /// Redis must be enabled externally
                // DO NOT DO THIS -> enabled: redisOpts, redis-server must be installed externally
                /// TODO: detect if redis-server is installed
                // enabled: redisServerIsInstalled,
            }
        }

        if (redisOpts.enabled) {
            this.opts = redisOpts.opts

            if (redisOpts.server) {
                this._client = redisOpts.client
                this._server = redisOpts.server
                this._store = redisOpts.store

                return
            }
        }
    }

    client() {
        if (!this._client) {
            const redis = require('redis')

            this._client = redis.createClient()
        }

        return this._client
    }

    server() {
        console.trace(this._server)
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
    close() {
        if (this._client) {
            console.log('good')
            this._client.quit()
        }

        if (this._server) {
            console.log('goodbye')
            return this._server.close()
        }

        return Promise.resolve()
    }
}

module.exports = RedisMiddleware
