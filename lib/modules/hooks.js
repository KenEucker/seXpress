/// Begin with the module name
const moduleName = 'hooks'
const moduleEmoji = '🪝'

/// Name the module init method which is used in logging
function InitHooks(initial, hooksOpts = {}) {
    /// dependencies are scoped to the module itself
    const { existsSync } = require('fs')

    this.config.hooks = this.getCoreOpts(moduleName, hooksOpts, initial)

    /// TODO: Create the nonce strategy that validates against uuid hashes from the authentication module

    if (this.config.hooks.enabled) {
        const controllersFolder =
            this.config.hooks.controllersFolder || this.config.folders.controllersFolder

        const zmq = require('zeromq')
        this.hooks = []
        const reservedHookMethods = [
            'addHook',
            'getHookInfo',
            'runHookServer',
            'sendHook',
            'spyHook',
            'triggerHook',
        ]

        this.config.hooks.mqServerPort = this.config.hooks.mqServerPort ?? 5555

        if (existsSync(controllersFolder)) {
            this.log.info(`${moduleEmoji} adding the hooks subdomain and controller`)
            this.config.subdomains['hooks'] = this.config.subdomains['hooks'] || {}
            this.config.subdomains['hooks'].controller = 'hooks'
            this.app.post(
                '/',
                this.requestHandler(
                    (req, res) => {
                        console.log('HOOKS REQUEST', { subdomain: res.locals.subdomain })
                    },
                    ['hooks'],
                ),
                this.isAuthenticatedHandler(),
            )

            const getHooksViewController = (view = 'index') => {
                return this.requestHandler(
                    (req, res) => {
                        if (view === 'profile' && !req.isAuthenticated()) return res.redirect('/')

                        const credentials = req.user
                        const loginData = {
                            credentials,
                            host: res.locals.host,
                            name: this.config.name,
                        }

                        const hookData = this.hooks.map((hook) => {
                            console.log({ hook })
                            if (reservedHookMethods.indexOf(hook) !== -1) {
                                return hook
                            }
                        })

                        return this.renderViewOrTemplate(`hooks/${view}`, { hooks: hookData }, res)
                    },
                    ['hooks'],
                )
            }
            this.app.get('/', getHooksViewController())
        }

        const addHook = (id, event = (d) => console.log(`${moduleEmoji} hook fired: ${id}`, d)) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`${moduleEmoji} cannot add protected hook id: ${id}`, id)
            }

            const existingHookIndex = this.hooks.indexOf(id)
            if (existingHookIndex === -1) {
                this.hooks[id] = []
            }

            if (event) {
                this.hooks[id].push(event)
            }
        }

        const getHookInfo = (id) => {
            const existingHook = this.hooks[id]
            if (existingHook) {
                const count = existingHook.length
                return {
                    id,
                    count,
                    registered: true,
                    type: count ? typeof existingHook[0] : 'empty',
                }
            }

            return {
                registered: false,
            }
        }

        const spyHook = (callback) => {
            const cb = (d) => {
                callback(Object.keys(this.hooks[id]), { result: d })
            }

            this.hooks[id].unshift(cb)
        }

        const triggerHook = async (id, data) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`${moduleEmoji} cannot trigger protected hook id: ${id}`, id)
            }

            const hooks = this.hooks[id]

            if (hooks?.length) {
                hooks.forEach(async (hook) => {
                    await hook(data)
                })
            }
        }

        const sendHook = async (
            id,
            recieve = true,
            hookServer = `tcp://localhost:${this.config.hooks.mqServerPort}`,
        ) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`${moduleEmoji} cannot send protected hook id: ${id}`, id)
            }

            const sock = new zmq.Request()
            sock.connect(hookServer)
            await sock.send(id)

            if (recieve) {
                const [result] = await sock.receive()

                this.log.info(`${moduleEmoji} Hook completed: ${id}`, result)
                return result
            }

            return id
        }

        const runHookServer = async () => {
            const sock = new zmq.Reply()

            await sock.bind('tcp://*:5555')

            for await (const [msg] of sock) {
                this.log.info(`${moduleEmoji} Received Hook: [${msg.toString()}]`)
                await sock.send(triggerHook(msg))
            }
        }

        runHookServer()

        this.hooks.addHook = addHook
        this.hooks.getHookInfo = getHookInfo
        this.hooks.triggerHook = triggerHook
        this.hooks.spyHook = spyHook
        this.hooks.sendHook = sendHook
        this.hooks.runHookServer = runHookServer

        this.log.info(
            `${moduleEmoji} Applicaition hooks have been enabled`,
            this.config.notifications,
        )
    }
}

module.exports = InitHooks
module.exports.module = 'hooks'
module.exports.emoji = moduleEmoji
module.exports.description = `Sets up the application to run webhooks at hooks.[host]`
module.exports.defaults = false
module.exports.version = '0.0.1'
