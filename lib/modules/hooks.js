/// Begin with the module name
const moduleName = 'hooks'

/// Name the module init method which is used in logging
function InitHooks(initial, hooksOpts = {}) {
    /// dependencies are scoped to the module itself
    const { existsSync } = require('fs')

    this.config.hooks = this.getCoreOpts(moduleName, hooksOpts, initial)

    /// TODO: Create the nonce strategy that validates against uuid hashes from the authentication module

    if (this.config.hooks.enabled) {
        const controllersFolder =
            this.config.hooks.controllersFolder || this.config.folders.controllersFolder
        this.config.hooks.mqServerPort = this.config.hooks.mqServerPort ?? 5555

        if (existsSync(controllersFolder)) {
            this.log.info(`🔗 adding the hooks subdomain and controller`)
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
							
							if 
                        })

                        return this.renderViewOrTemplate(`hooks/${view}`, hookData, res)
                    },
                    ['hooks'],
                )
            }
            this.app.get('/', getHooksViewController())
        }

        const zmq = require('zeromq')
        this.hooks = []
		const reservedHookMethods = [
			'addHook',
			'addHookData',
			'addHookEvent',
			'runHookServer',
			'sendHook',
			'spyHook',
			'triggerHook',
		]

        const addHook = (id, initialEvent) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`cannot add protected hook id: ${id}`, id)
            }

            const existingHookIndex = this.hooks.indexOf(id)
            if (existingHookIndex !== -1) {
                this.hooks[id] = []
            }

            if (initialEvent) {
                this.hooks[id].push(initialEvent)
            }
        }

        const addHookEvent = (id, event = (d) => console.log(`hook fired: ${id}`, d)) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`cannot attach to protected hook id: ${id}`, id)
            }
            this.hooks[id].push(event)
        }

        const addHookData = (id, data = (d) => console.log(`hook data requested: ${id}`, d)) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`cannot attach to protected hook id: ${id}`, id)
            }
            this.hooks[id] = data
        }

        const spyHook = (callback) => {
			const cb = (d) => {
				callback(Object.keys(this.hooks[id]), {result: d})
			}

            this.hooks[id].unshift(cb)
        }

        const triggerHook = (id, data) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`cannot trigger protected hook id: ${id}`, id)
            }

            const hooks = this.hooks[id]

            if (hooks?.length) {
                hooks.forEach((hook) => {
                    hook(data)
                })
            }
        }

        const sendHook = (id, recieve = true) => {
            if (reservedHookMethods.indexOf(id) !== -1) {
                this.log.error(`cannot send protected hook id: ${id}`, id)
            }

            const sock = new zmq.Request()
            sock.connect(`tcp://localhost:${this.config.hooks.mqServerPort}`)
            await sock.send(id)

            if (recieve) {
                const [result] = await sock.receive()

                this.log.info(`Hook completed: ${id}`, result)
                return result
            }

            return id
        }

        const runHookServer = async () => {
            const sock = new zmq.Reply()

            await sock.bind('tcp://*:5555')

            for await (const [msg] of sock) {
                this.log.info('Received Hook' + ': [' + msg.toString() + ']')
                await sock.send(triggerHook(msg))
            }
        }

        runHookServer()

        this.hooks.addHook = addHook
        this.hooks.addHookEvent = addHookEvent
        this.hooks.addHookData = addHookData
        this.hooks.triggerHook = triggerHook
        this.hooks.spyHook = spyHook
        this.hooks.sendHook = sendHook
        this.hooks.runHookServer = runHookServer
    }
}

module.exports = InitHooks
module.exports.module = 'hooks'
module.exports.description = `Sets up the application to run webhooks at hooks.[host]`
module.exports.defaults = false
module.exports.version = '0.0.1'
