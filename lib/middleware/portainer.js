class PortainerMiddleware {
    constructor(portainerOpts = {}) {
        this.opts = {}

        if (typeof portainerOpts === 'boolean') {
            portainerOpts = {
                /// DO NOT EXPLICITELY RUN THIS CONTAINER
                /// Portainer must be enabled externally
                /// TODO: detect if docker is installed
                // DO NOT DO THIS -> enabled: portainerOpts, docker must be installed externally
                portainerDockerImage: 'portainer/portainer-ce:2.0.0',
            }
        } else {
            portainerOpts.portainerDockerImage = portainerOpts.portainerDockerImage
                ? portainerOpts.portainerDockerImage
                : 'portainer/portainer-ce:2.0.0'
        }

        if (portainerOpts.enabled) {
            if (portainerOpts.server) {
                console.log({ portainerOpts })
            } else {
                const { existsSync } = require('fs')
                const { join, resolve } = require('path')
                this.opts = portainerOpts
                this.opts.log = true

                this.opts.dockerFolder = resolve('./docker/portainer')
                this.opts.portainerDockerFile = this.opts.portainerDockerFile
                    ? this.opts.portainerDockerFile
                    : join(this.opts.dockerFolder, 'docker-compose.yaml')
                this.opts.publicPort = this.opts.publicPort ? this.opts.publicPort : 80
                this.opts.sslPort = this.opts.sslPort ? this.opts.sslPort : 443
                this.opts.portainerPort = this.opts.portainerPort ? this.opts.portainerPort : 9000
                this.opts.edgePort = this.opts.edgePort ? this.opts.edgePort : 8000
                this.opts.subdomain = this.opts.subdomain ? this.opts.subdomain : 'portainer'
                this.opts.host = this.opts.host ? this.opts.host : 'localhost'

                if (!existsSync(this.opts.dockerFolder)) {
                    const mkdirp = require('mkdirp')
                    mkdirp.sync(this.opts.dockerFolder)
                }

                this.opts.composeOpts = {
                    cwd: this.opts.dockerFolder,
                    log: this.opts.log,
                    config: this.opts.portainerDockerFile,
                }
            }
        }
    }

    async init(middlewares) {
        this.compose = require('docker-compose')
        const { writeFileSync, existsSync } = require('fs')

        /// TODO: add the portainer subdomain and point it to portainer install

        if (!existsSync(this.opts.portainerDockerFile)) {
            const { stringify: yamilify } = require('yaml')
            const portainerDockerYaml = {
                version: '3.3',
                services: {
                    traefik: {
                        container_name: 'traefik',
                        image: 'traefik:v2.2.8',
                        command: [
                            '--entrypoints.web.address=:80',
                            '--entrypoints.websecure.address=:443',
                            '--providers.docker',
                            '--log.level=DEBUG',
                            '--certificatesresolvers.leresolver.acme.httpchallenge=true',
                            `--certificatesresolvers.leresolver.acme.email=${this.opts.email}`,
                            '--certificatesresolvers.leresolver.acme.storage=./acme.json',
                            '--certificatesresolvers.leresolver.acme.httpchallenge.entrypoint=web',
                        ],
                        ports: [
                            `${this.opts.publicPort}:${this.opts.publicPort}`,
                            `${this.opts.sslPort}:${this.opts.sslPort}`,
                        ],
                        volumes: [
                            '/var/run/docker.sock:/var/run/docker.sock:ro',
                            './acme.json:/acme.json',
                        ],
                        labels: [
                            'traefik.http.routers.http-catchall.rule=hostregexp(`{host:.+}`)',
                            'traefik.http.routers.http-catchall.entrypoints=web',
                            'traefik.http.routers.http-catchall.middlewares=redirect-to-https',
                            'traefik.http.middlewares.redirect-to-https.redirectscheme.scheme=https',
                        ],
                    },
                    portainer: {
                        image: this.opts.portainerDockerImage,
                        command: '-H unix:///var/run/docker.sock',
                        restart: 'always',
                        volumes: [
                            '/var/run/docker.sock:/var/run/docker.sock',
                            'portainer_data:/data',
                        ],
                        labels: [
                            /// Frontend
                            'traefik.enable=true',
                            `traefik.http.routers.frontend.rule=Host(\`${this.opts.subdomain}.${this.opts.host}\`)`,
                            `traefik.http.services.frontend.loadbalancer.server.port=${this.opts.portainerPort}`,
                            'traefik.http.routers.frontend.entrypoints=websecure',
                            'traefik.http.routers.frontend.service=frontend',
                            'traefik.http.routers.frontend.tls.certresolver=leresolver',
                            /// Edge
                            `traefik.http.routers.edge.rule=Host(\`edge.${this.opts.host}\`)`,
                            `traefik.http.services.edge.loadbalancer.server.port=${this.opts.edgePort}`,
                            'traefik.http.routers.edge.entrypoints=websecure',
                            'traefik.http.routers.edge.service=edge',
                            'traefik.http.routers.edge.tls.certresolver=leresolver',
                        ],
                    },
                },
                volumes: {
                    portainer_data: {},
                },
            }

            console.log('writing new portainer docker file', this.opts.portainerDockerFile)
            writeFileSync(this.opts.portainerDockerFile, yamilify(portainerDockerYaml))
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
        return new Promise(async (resolve, reject) => {
            if (this.opts.server && !this.opts.persist) {
                console.log('RYING portainer')
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

module.exports = PortainerMiddleware
