class PlausibleMiddleware {
    constructor(plausibleOpts = {}) {
        this.opts = {}

        if (typeof plausibleOpts === 'boolean') {
            plausibleOpts = {
                /// DO NOT EXPLICITELY RUN THIS CONTAINER
                /// Wordpress must be enabled externally
                /// TODO: detect if docker is installed
                // DO NOT DO THIS -> enabled: plausibleOpts, docker must be installed externally
                plausibleDockerImage: 'plausible',
            }
        }

        if (plausibleOpts.enabled) {
            if (plausibleOpts.server) {
                console.log({ plausibleOpts })
            } else {
                const { existsSync } = require('fs')
                const { join, resolve } = require('path')
                this.opts = plausibleOpts
                this.opts.log = true

                this.opts.dockerFolder = resolve('./docker/plausible')
                this.opts.plausibleDockerFile = this.opts.plausibleDockerFile
                    ? this.opts.plausibleDockerFile
                    : join(this.opts.dockerFolder, 'docker-compose.yaml')
				this.opts.plausibleEnvFile = this.opts.plausibleEnvFile
					? this.opts.plausibleEnvFile
					: join(this.opts.dockerFolder, 'plausible-conf.env')
                this.opts.plausibleDockerImage = this.opts.plausibleDockerImage
                    ? this.opts.plausibleDockerImage
                    : 'plausible'
                this.opts.plausibleDockerName = this.opts.plausibleDockerName
                    ? this.opts.plausibleDockerName
                    : this.opts.plausibleDockerImage
                this.opts.plausibleDockerContainerName = this.opts.plausibleDockerContainerName
                    ? this.opts.plausibleDockerContainerName
                    : `${this.opts.plausibleDockerName}_container`
                this.opts.publicPort = this.opts.publicPort ? this.opts.publicPort : 3216 // WP
                this.opts.exposePort = this.opts.exposePort ? this.opts.exposePort : 80

                if (!existsSync(this.opts.dockerFolder)) {
                    const mkdirp = require('mkdirp')
                    mkdirp.sync(this.opts.dockerFolder)
                }

                this.opts.composeOpts = {
                    cwd: this.opts.dockerFolder,
                    log: this.opts.log,
                    config: this.opts.plausibleDockerFile,
                }
            }
        }
    }

    async init(middlewares) {
        this.compose = require('docker-compose')
        const { writeFileSync, existsSync } = require('fs')

        /// TODO: add the plausible subdomain and point it to plausible install

        if (!existsSync(this.opts.plausibleDockerFile)) {
            const { stringify: yamilify } = require('yaml')
            const plausibleDockerYaml = {
                version: '3.3',
                services: {
                    mail: {
                        image: 'bytemark/smtp',
                        restart: 'always',
                    },
                    plausible_db: {
                        image: 'postgres:12',
                        restart: 'always',
                        volumes: ['db-data:/var/lib/postgresql/data'],
                        environment: ['POSTGRES_PASSWORD=postgres'],
                    },
                    plausible_events_db: {
                        image: 'yandex/clickhouse-server:21.3.2.5',
                        restart: 'always',
                        volumes: [
                            'event-data:/var/lib/clickhouse',
                            './clickhouse/clickhouse-config.xml:/etc/clickhouse-server/config.d/logging.xml:ro',
                            './clickhouse/clickhouse-user-config.xml:/etc/clickhouse-server/users.d/logging.xml:ro',
                        ],
                        ulimits: {
                            nofile: {
                                soft: 262144,
                                hard: 262144,
                            },
                        },
                    },
                    plausible: {
                        image: 'plausible/analytics:latest',
                        restart: 'always',
                        command:
                            'sh -c "sleep 10 && /entrypoint.sh db createdb && /entrypoint.sh db migrate && /entrypoint.sh db init-admin && /entrypoint.sh run"',
                        depends_on: ['plausible_db', 'plausible_events_db', 'mail'],
                        ports: ['8000:8000'],
                        env_file: ['plausible-conf.env'],
                    },
                },
                volumes: {
                    'db-data': {
                        driver: 'local',
                    },
                    'event-data': {
                        driver: 'local',
                    },
                    geoip: {
                        driver: 'local',
                    },
                },
            }

			const plausibleEnv = `
			ADMIN_USER_EMAIL=replace-me
			ADMIN_USER_NAME=replace-me
			ADMIN_USER_PWD=replace-me
			BASE_URL=replace-me
			SECRET_KEY_BASE=replace-me
			`

            console.log('writing new plausible docker file', this.opts.plausibleDockerFile)
            writeFileSync(this.opts.plausibleDockerFile, yamilify(plausibleDockerYaml))
            console.log('writing new plausible env file', this.opts.plausibleEnvFile)
            writeFileSync(this.opts.plausibleEnvFile, yamilify(plausibleEnv))
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
        if (this.opts.server && !this.opts.persist) {
            try {
                console.log('plausible closing')
                await this.compose.down(this.opts.composeOpts).then((result) => {
                    console.log({ result })
                })
                console.log('plausible closed')
            } catch (e) {
                console.log('plausible errored', e)
            }
        }
    }
}

module.exports = PlausibleMiddleware
