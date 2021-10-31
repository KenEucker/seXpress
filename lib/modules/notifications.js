/// Begin with the module name
const moduleName = 'notifications'
const moduleEmoji = '📌'

const moduleHooks = {
    subscribe: `${moduleName}:subscribe`,
    unsubscribe: `${moduleName}:unsubscribe`,
    notify: `${moduleName}:notify`,
    subscribers: `${moduleName}:subscribers`,
}

/// Name the module init method which is used in logging
function InitNotifications(initial, notificationsOpts = {}) {
    this.config.notifications = this.getCoreOpts(moduleName, notificationsOpts, initial)

    if (this.config.notifications.enabled) {
        const webpush = require('web-push')

        this.config.notifications = this.config.notifications ?? { enabled: true }
        this.config.notifications.messages = this.config.notifications.messages ?? {}
        this.config.notifications.gcmApiKey =
            this.config.notifications.gcmApiKey ?? this.config.authentication.google.googleApiKey
        this.config.notifications.messages.serviceWorkerPrefix =
            this.config.notifications.messages.serviceWorkerPrefix ?? 'Service Worker :: '

        if (
            !(this.config.notifications.vapidPublicKey && this.config.notifications.vapidPrivateKey)
        ) {
            /// TODO: (per domain?)
            // VAPID keys should be generated only once.
            const vapidKeys = webpush.generateVAPIDKeys()

            this.config.notifications.vapidPublicKey = vapidKeys.publicKey
            this.config.notifications.vapidPrivateKey = vapidKeys.privateKey

            this.log.info(
                `${moduleEmoji} VAPID Keys generated (SAVE THESE): ${JSON.stringify(vapidKeys)}`,
            )
        } else {
            this.log.debug(`${moduleEmoji} VAPID Keys loaded from configuration`, {
                publicKey: this.config.notifications.vapidPublicKey,
                privateKey: this.config.notifications.vapidPrivateKey,
            })
        }

        if (this.config.notifications.gcmApiKey) {
            webpush.setGCMAPIKey(this.config.notifications.gcmApiKey)
            this.log.debug(
                `${moduleEmoji} notifications gmc API key has been set`,
                this.config.notifications.gcmApiKey,
            )
        }

        const sendNotificationToSubscription = (subscription, title, message) => {
            return webpush
                .sendNotification(subscription, JSON.stringify({ title, message }))
                .catch((error) => {
                    this.log.error(error.stack)
                })
        }

        const subscribeToNotifications = (req, res) => {
            const { host, subdomain } = res.locals
            const subscription = {
                host,
                domain: subdomain,
                ...req.body,
            }

            res.status(201).json({})
            this.hook(moduleHooks.subscribe, subscription)

            const title = 'Subscribed!'
            const message = `You have been subscribed to notifications from ${
                subdomain ? `${subdomain}.` : ''
            }${host}`

            this.log.info(`${moduleEmoji} browser user subscribed to notifications`, {
                subscription,
            })

            sendNotificationToSubscription(subscription, title, message)
        }

        const sendWorkerJS = (req, res) => {
            const { host, subdomain } = res.locals
            const serviceWorkerLoadedMessage =
                this.config.notifications.messages.serviceWorkerLoaded ??
                `${moduleEmoji} loaded the service worker from ${subdomain}.${host}!`

            res.set('content-type', 'text/javascript')

            return res.send(`
			(() => {
				const serviceWorkerPrefix = '${this.config.notifications.messages.serviceWorkerPrefix}'
				console.log(serviceWorkerPrefix + '${serviceWorkerLoadedMessage}')

				self.addEventListener('push', ev => {
					let event = {title: 'push recieved', message: ev.data.text()}
					try {
						event = ev.data.json()
					} catch(e) {}
					console.log(serviceWorkerPrefix + 'Recieved push from ${subdomain}.${host}', event)
					self.registration.showNotification(event.title, {
						body: event.message,
						icon: '${host}/public/favicon.ico'
					})
				})
			})()`)
        }

        const sendSubscribeJS = (req, res) => {
            const { host, subdomain } = res.locals
            const serviceWorkerRegisteringMessage =
                this.config.notifications.messages.serviceWorkerRegistering ??
                `${moduleEmoji} registering service worker for ${subdomain}.${host}`
            const serviceWorkerRegisteredMessage =
                this.config.notifications.messages.serviceWorkerRegistered ??
                `${moduleEmoji} registered service worker for ${subdomain}.${host}`

            res.set('content-type', 'text/javascript')

            return res.send(`
			(() => {
				const publicVapidKey = '${this.config.notifications.vapidPublicKey}'
				const serviceWorkerPrefix = '${this.config.notifications.messages.serviceWorkerPrefix}'
				
				const urlBase64ToUint8Array = (base64String) => {
					var padding = '='.repeat((4 - base64String.length % 4) % 4)
					var base64 = (base64String + padding)
						.replace(/\-/g, '+')
						.replace(/_/g, '/')
				
					var rawData = window.atob(base64)
					var outputArray = new Uint8Array(rawData.length)
				
					for (var i = 0; i < rawData.length; ++i) {
						outputArray[i] = rawData.charCodeAt(i)
					}
					return outputArray
				}

				async function run() {
					console.log(serviceWorkerPrefix + 'registering worker.js file from host ${subdomain}.${host}')
					const registration = await navigator.serviceWorker.register('/worker.js', {scope: '/'})
					console.log(serviceWorkerPrefix + '${serviceWorkerRegisteredMessage}')
				
					await navigator.serviceWorker.ready
					console.log(serviceWorkerPrefix + 'registering push')
					const subscription = await registration.pushManager.
					subscribe({
						userVisibleOnly: true,
						applicationServerKey: urlBase64ToUint8Array(publicVapidKey)
					})
					console.log(serviceWorkerPrefix + 'registered push')
				
					console.log(serviceWorkerPrefix + 'sending push')
					await fetch('/subscribe', {
						method: 'POST',
						body: JSON.stringify(subscription),
						headers: {
							'content-type': 'application/json'
						}
					})
					console.log(serviceWorkerPrefix + 'sent push')
				}

				window.addEventListener('load', () => {
					if ('serviceWorker' in navigator) {
						console.log(serviceWorkerPrefix + '${serviceWorkerRegisteringMessage}')
					
						if (navigator.serviceWorker?.controller?.state !== 'activated') {
							run().catch((error) => {
								if (error) console.error(error)
							})
						}
					}
				})
			})()`)
        }

        const sendNotificationToAllSubscribers = (title, message, domain) => {
            this.hook(
                moduleHooks.subscribers,
                async (subscribersHook) => {
                    if (subscribersHook?.length) {
                        const subscribers = await subscribersHook[0]()
                        subscribers.forEach((subscriber) => {
                            if (domain && subscriber.domain === domain) {
                                sendNotificationToSubscription(
                                    subscriber.subscription,
                                    title,
                                    message,
                                )
                            }
                        })
                    }
                },
                false,
            )
        }

        this.hook(moduleHooks.notify, (notification) => {
            if (notification.subscription) {
                sendNotificationToSubscription(
                    notification.subscription,
                    notification.title,
                    notification.message,
                )
            } else if (notification.domain) {
                sendNotificationToAllSubscribers(
                    notification.title,
                    notification.message,
                    notification.domain,
                )
            }
        })

        this.route('/subscribe', subscribeToNotifications, 'post')
        this.route('/unsubscribe', subscribeToNotifications, 'post')
        this.route('/subscribe.js', sendSubscribeJS, 'get')
        this.route('/worker.js', sendWorkerJS, 'get')

        /// TODO: Set this for all subdomains
        webpush.setVapidDetails(
            `mailto:${this.config.author.email}`,
            this.config.notifications.vapidPublicKey,
            this.config.notifications.vapidPrivateKey,
        )

        this.notifications = {
            webpush,
            sendNotificationToAllSubscribers,
            sendNotificationToSubscription,
        }
        this.log.info(
            `${moduleEmoji} Browser notifications have been enabled`,
            this.config.notifications,
        )
    }
}

module.exports = InitNotifications
module.exports.module = moduleName
module.exports.emoji = moduleEmoji
module.exports.description =
    'Subscribes users to browser notifications and sends notifications to subscribers'
module.exports.defaults = false
module.exports.hooks = moduleHooks
module.exports.version = '0.0.1'
