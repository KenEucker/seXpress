class SupabaseMiddleware {
    constructor(supabaseOpts = {}) {
        this.opts = {}

        if (typeof supabaseOpts === 'boolean') {
            supabaseOpts = {
                enabled: supabaseOpts,
            }
        }

        supabaseOpts.log = typeof supabaseOpts.log !== 'undefined' ? supabaseOpts.log : true

        if (supabaseOpts.enabled) {
            if (supabaseOpts.server) {
                this._client = supabaseOpts.client
                this._server = supabaseOpts.server
                this._store = supabaseOpts.store
                this.opts = supabaseOpts.opts
                console.log({ supabaseOpts: this.opts })
            } else {
                this.opts = supabaseOpts
            }
        }
    }

    async init() {
        const { existsSync, writeFileSync } = require('fs')
        const { join, resolve } = require('path')
        this.compose = require('docker-compose')

        this.opts.dockerFolder = resolve('./docker/supabase')
        this.opts.supabaseDockerFile = this.opts.supabaseDockerFile
            ? this.opts.supabaseDockerFile
            : join(this.opts.dockerFolder, 'docker-compose.yaml')
        this.opts.supabaseDockerVolumesFolder = this.opts.supabaseDockerVolumesFolder
            ? this.opts.supabaseDockerVolumesFolder
            : join(this.opts.dockerFolder, 'volumes')
        this.opts.publicPort = this.opts.publicPort ? this.opts.publicPort : 6379
        this.opts.exposePort = this.opts.exposePort ? this.opts.exposePort : 6379
        this.opts.composeOpts = {
            cwd: this.opts.dockerFolder,
            log: this.opts.log,
            config: this.opts.supabaseDockerFile,
        }

        if (!existsSync(this.opts.dockerFolder)) {
            const mkdirp = require('mkdirp')
            mkdirp.sync(this.opts.dockerFolder)
            mkdirp.sync(`${this.opts.dockerFolder}/volumes`)
        }

        if (!existsSync(this.opts.supabaseDockerFile)) {
            const { stringify: yamilify } = require('yaml')
            const KONG_HTTP_PORT = this.opts.KONG_HTTP_PORT ?? 8000
            const KONG_HTTPS_PORT = this.opts.KONG_HTTPS_PORT ?? 8443
            const POSTGRES_PORT = this.opts.POSTGRES_PORT ?? 5432
            const ENABLE_PHONE_SIGNUP = this.opts.ENABLE_PHONE_SIGNUP ?? 'false'
            const ENABLE_PHONE_AUTOCONFIRM = this.opts.ENABLE_PHONE_AUTOCONFIRM ?? 'false'
            const ENABLE_EMAIL_AUTOCONFIRM = this.opts.ENABLE_EMAIL_AUTOCONFIRM ?? 'false'
            const ENABLE_EMAIL_SIGNUP = this.opts.ENABLE_EMAIL_SIGNUP ?? 'true'
            const JWT_EXPIRY = this.opts.JWT_EXPIRY ?? 3600
            const DISABLE_SIGNUP = this.opts.DISABLE_SIGNUP ?? 'false'
            const ADDITIONAL_REDIRECT_URLS = this.opts.ADDITIONAL_REDIRECT_URLS ?? ''

            /// Required (all constants below)
            const JWT_SECRET =
                this.opts.JWT_SECRET ?? 'super-secret-jwt-token-with-at-least-32-characters-long'

            if (!(this.opts.ANON_KEY && this.opts.SERVICE_KEY)) {
                const fiveYears = 60 * 60 * 24 * 365 * 5
                const iat = new Date().getTime() / 1000
                const exp = iat + fiveYears

                const jwt = require('jwt-simple')

                this.opts.ANON_KEY = jwt.encode({ iat, exp, role: 'anon' }, JWT_SECRET)
                this.opts.SERVICE_KEY = jwt.encode({ iat, exp, role: 'service_role' }, JWT_SECRET)
            }

            const ANON_KEY = this.opts.ANON_KEY
            const SERVICE_KEY = this.opts.SERVICE_KEY
            const POSTGRES_PASSWORD =
                this.opts.POSTGRES_PASSWORD ?? 'super-secret-and-long-postgres-password'
            const SITE_URL = this.opts.SITE_URL ?? 'http://localhost:3000'
            const SMTP_HOST = this.opts.SMTP_HOST ?? ''
            const SMTP_SENDER_NAME = this.opts.SMTP_SENDER_NAME ?? ''
            const SMTP_PASS = this.opts.SMTP_PASS ?? ''
            const SMTP_USER = this.opts.SMTP_USER ?? ''
            const SMTP_PORT = this.opts.SMTP_PORT ?? ''
            const SMTP_ADMIN_EMAIL = this.opts.SMTP_ADMIN_EMAIL ?? ''

            const supabaseDockerYaml = {
                version: '3.3',
                services: {
                    kong: {
                        container_name: 'supabase-kong',
                        image: 'kong:2.1',
                        restart: 'unless-stopped',
                        ports: [`${KONG_HTTP_PORT}:8000/tcp`, `${KONG_HTTPS_PORT}:8443/tcp`],
                        volumes: [`./volumes/kong.yml:/var/lib/kong/kong.yml`],
                        environment: {
                            KONG_DATABASE: `"off"`,
                            KONG_DECLARATIVE_CONFIG: '/var/lib/kong/kong.yml',
                            KONG_DNS_ORDER: 'LAST,A,CNAME',
                            KONG_PLUGINS: 'request-transformer,cors,key-auth',
                        },
                    },
                    auth: {
                        container_name: 'supabase-auth',
                        image: 'supabase/gotrue:v2.1.8',
                        depends_on: ['db'],
                        restart: 'unless-stopped',
                        environment: {
                            GOTRUE_API_HOST: '0.0.0.0',
                            GOTRUE_API_PORT: 9999,

                            GOTRUE_DB_DRIVER: 'postgres',
                            GOTRUE_DB_DATABASE_URL: `postgres://postgres:${POSTGRES_PASSWORD}@db:5432/postgres?sslmode=disable&search_path=auth"`,

                            GOTRUE_SITE_URL: SITE_URL,
                            GOTRUE_URI_ALLOW_LIST: ADDITIONAL_REDIRECT_URLS,
                            GOTRUE_DISABLE_SIGNUP: DISABLE_SIGNUP,

                            GOTRUE_JWT_SECRET: JWT_SECRET,
                            GOTRUE_JWT_EXP: JWT_EXPIRY,
                            GOTRUE_JWT_DEFAULT_GROUP_NAME: 'authenticated',

                            GOTRUE_EXTERNAL_EMAIL_ENABLED: ENABLE_EMAIL_SIGNUP,
                            GOTRUE_MAILER_AUTOCONFIRM: ENABLE_EMAIL_AUTOCONFIRM,
                            GOTRUE_SMTP_ADMIN_EMAIL: SMTP_ADMIN_EMAIL,
                            GOTRUE_SMTP_HOST: SMTP_HOST,
                            GOTRUE_SMTP_PORT: SMTP_PORT,
                            GOTRUE_SMTP_USER: SMTP_USER,
                            GOTRUE_SMTP_PASS: SMTP_PASS,
                            GOTRUE_SMTP_SENDER_NAME: SMTP_SENDER_NAME,
                            GOTRUE_MAILER_URLPATHS_INVITE: '/auth/v1/verify',
                            GOTRUE_MAILER_URLPATHS_CONFIRMATION: '/auth/v1/verify',
                            GOTRUE_MAILER_URLPATHS_RECOVERY: '/auth/v1/verify',
                            GOTRUE_MAILER_URLPATHS_EMAIL_CHANGE: '/auth/v1/verify',

                            GOTRUE_EXTERNAL_PHONE_ENABLED: ENABLE_PHONE_SIGNUP,
                            GOTRUE_SMS_AUTOCONFIRM: ENABLE_PHONE_AUTOCONFIRM,
                        },
                    },
                    rest: {
                        container_name: 'supabase-rest',
                        image: 'postgrest/postgrest:v8.0.0',
                        depends_on: ['db'],
                        restart: 'unless-stopped',
                        environment: {
                            PGRST_DB_URI:
                                'postgres://postgres:${POSTGRES_PASSWORD}@db:5432/postgres',
                            PGRST_DB_SCHEMA: 'public, storage',
                            PGRST_DB_ANON_ROLE: 'anon',
                            PGRST_JWT_SECRET: JWT_SECRET,
                        },
                    },
                    realtime: {
                        container_name: 'supabase-realtime',
                        image: 'supabase/realtime:v0.15.0',
                        depends_on: ['db'],
                        restart: 'unless-stopped',
                        environment: {
                            DB_HOST: 'db',
                            DB_PORT: 5432,
                            DB_NAME: 'postgres',
                            DB_USER: 'postgres',
                            DB_PASSWORD: POSTGRES_PASSWORD,
                            SLOT_NAME: 'supabase_realtime',
                            PORT: 4000,
                            SECURE_CHANNELS: 'true',
                            JWT_SECRET: JWT_SECRET,
                        },
                    },
                    storage: {
                        container_name: 'supabase-storage',
                        image: 'supabase/storage-api:v0.9.3',
                        depends_on: ['db', 'rest'],
                        restart: 'unless-stopped',
                        volumes: [`./volumes/storage:/var/lib/storage`],
                        environment: {
                            ANON_KEY,
                            SERVICE_KEY,
                            POSTGREST_URL: 'http://rest:3000',
                            PGRST_JWT_SECRET: JWT_SECRET,
                            DATABASE_URL:
                                'postgres://postgres:${POSTGRES_PASSWORD}@db:5432/postgres',
                            PGOPTIONS: '-c search_path=storage',
                            FILE_SIZE_LIMIT: 52428800,
                            STORAGE_BACKEND: 'file',
                            FILE_STORAGE_BACKEND_PATH: '/var/lib/storage',
                            PROJECT_REF: 'stub',
                            REGION: 'stub',
                            GLOBAL_S3_BUCKET: 'stub',
                        },
                    },
                    db: {
                        container_name: 'supabase-db',
                        image: 'supabase/postgres:13.3.0',
                        restart: 'unless-stopped',
                        ports: [`${POSTGRES_PORT}:5432`],
                        volumes: [
                            './volumes/db/data:/var/lib/postgresql/data',
                            './volumes/db/init:/docker-entrypoint-initdb.d',
                        ],
                        environment: {
                            POSTGRES_PASSWORD: POSTGRES_PASSWORD,
                        },
                        command: 'postgres -c wal_level=logical',
                    },
                },
            }

            const supabaseKongYaml = {
                _format_version: '1.1',
                services: [
                    {
                        name: 'auth-v1-open',
                        url: 'http://auth:9999/verify',
                        routes: [
                            {
                                name: 'auth-v1-open',
                                strip_path: true,
                                paths: ['/auth/v1/verify'],
                            },
                        ],
                        plugins: [{ name: 'cors' }],
                    },
                    {
                        name: 'auth-v1-open-callback',
                        url: 'http://auth:9999/callback',
                        routes: [
                            {
                                name: 'auth-v1-open-callback',
                                strip_path: true,
                                paths: ['/auth/v1/callback'],
                            },
                        ],
                        plugins: [{ name: 'cors' }],
                    },
                    {
                        name: 'auth-v1-open-authorize',
                        url: 'http://auth:9999/authorize',
                        routes: [
                            {
                                name: 'auth-v1-open-authorize',
                                strip_path: true,
                                paths: ['/auth/v1/authorize'],
                            },
                        ],
                        plugins: [{ name: 'cors' }],
                    },
                    {
                        name: 'auth-v1',
                        _comment: 'GoTrue: /auth/v1/* -> http://auth:9999/*',
                        url: 'http://auth:9999/',
                        routes: [{ name: 'auth-v1-all', strip_path: true, paths: ['/auth/v1/'] }],
                        plugins: [
                            { name: 'cors' },
                            {
                                name: 'key-auth',
                                config: {
                                    hide_credentials: false,
                                },
                            },
                        ],
                    },
                    {
                        name: 'rest-v1',
                        _comment: 'PostgREST: /rest/v1/* -> http://rest:3000/*',
                        url: 'http://rest:3000/',
                        routes: [
                            {
                                name: 'rest-v1-all',
                                strip_path: true,
                                paths: ['/rest/v1/'],
                            },
                        ],
                        plugins: [
                            {
                                name: 'cors',
                            },
                            {
                                name: 'key-auth',
                                config: {
                                    hide_credentials: true,
                                },
                            },
                        ],
                    },
                    {
                        name: 'realtime-v1',
                        _comment: 'Realtime: /realtime/v1/* -> ws://realtime:4000/socket/*',
                        url: 'http://realtime:4000/socket/',
                        routes: [
                            {
                                name: 'realtime-v1-all',
                                strip_path: true,
                                paths: ['/realtime/v1/'],
                            },
                        ],
                        plugins: [
                            { name: 'cors' },
                            {
                                name: 'key-auth',
                                config: {
                                    hide_credentials: false,
                                },
                            },
                        ],
                    },
                    {
                        name: 'storage-v1',
                        _comment: 'Storage: /storage/v1/* -> http://storage-api:5000/*',
                        url: 'http://storage:5000/',
                        routes: [
                            { name: 'storage-v1-all', strip_path: true, paths: ['/storage/v1/'] },
                        ],
                        plugins: [{ name: 'cors' }],
                    },
                ],
                consumers: [
                    {
                        username: 'anon',
                        keyauth_credentials: [
                            {
                                key: ANON_KEY,
                            },
                        ],
                    },
                    {
                        username: 'service_role',
                        keyauth_credentials: [
                            {
                                key: SERVICE_KEY,
                            },
                        ],
                    },
                ],
            }

            console.log('writing new supabase docker file', this.opts.supabaseDockerFile)
            writeFileSync(this.opts.supabaseDockerFile, yamilify(supabaseDockerYaml))
            writeFileSync(
                join(this.opts.supabaseDockerVolumesFolder, 'kong.yml'),
                yamilify(supabaseKongYaml),
            )
        }

        await this.compose.upAll(this.opts.composeOpts).then(
            () => {
                console.log('docker container for supabase has started')
                this._server = true
            },
            (err) => {
                console.log('docker container for supabase failed to start', err)
                this._server = false
            },
        )
    }

    client() {
        if (!this._client) {
            const { createClient } = require('@supabase/supabase-js')

            this._client = createClient(this.opts.endpoint, this.opts.publicKey)
        }

        return this._client
    }

    server() {
        if (!this._server) {
        }

        return this._server
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
                console.log('supabase closing')
                await this.compose.stop(this.opts.composeOpts).then(
                    () => {
                        console.log('supabase docker container stopped')
                    },
                    (err) => {
                        console.log('could not stop supabase docker image', {
                            err,
                        })
                    },
                )
                console.log('supabase closed')
            } catch (e) {
                console.log('supabase error', { e })
            }
        }
    }
}

module.exports = SupabaseMiddleware
