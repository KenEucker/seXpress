/// Begin with the module name
const moduleName = 'notifications'

/// Name the module init method which is used in logging
function InitNotifications(initial, notificationsOpts = {}) {
    this.config.notifications = this.getCoreOpts(moduleName, notificationsOpts, initial)

    if (this.config.notifications.enabled) {
        const webpush = require('web-push')

        this.config.notifications = this.config.notifications || { enabled: true }
        this.config.notifications.vapid = this.config.notifications.vapid || {}
        this.config.notifications.messages = this.config.notifications.messages || {}
        this.config.notifications.gcmApikey =
            this.config.notifications.gcmApikey ?? this.config.authentication.google.googleApiKey

        if (
            !this.config.notifications.vapid.publicKey &&
            !this.config.notifications.vapid.privateKey
        ) {
            /// TODO: (per domain?)
            // VAPID keys should be generated only once.
            const vapidKeys = webpush.generateVAPIDKeys()

            this.config.notifications.vapid.publicKey = vapidKeys.publicKey
            this.config.notifications.vapid.privateKey = vapidKeys.privateKey

            this.log.debug('VAPID Keys generated', { vapidKeys })
        }

        if (this.config.notifications.gcmApikey) {
            webpush.setGCMAPIKey(this.config.notifications.gcmApikey)
            this.log.debug(
                'notifications gmc API key has been set',
                this.config.notifications.gcmApikey,
            )
        }

        const subscribeToNotifications = (req, res) => {
            const { host, subdomain } = res.locals
            const subscription = req.body
            res.status(201).json({})
            const payload = JSON.stringify({
                title: 'Subscribed!',
                message: `You have been subscribed to notifications from ${
                    subdomain ? `${subdomain}.` : ''
                }${host}`,
            })

            this.log.info('browser user subscribed to notifications', { subscription })

            webpush.sendNotification(subscription, payload).catch((error) => {
                this.log.error(error.stack)
            })
        }

        const sendWorkerJS = (req, res) => {
            const { host, subdomain } = res.locals
            const serviceWorkerLoadedMessage =
                this.config.notifications.messages.serviceWorkerLoaded ??
                `loaded the service worker from ${subdomain}.${host}!`

            res.set('content-type', 'text/javascript')

            return res.send(`
			(() => {
				const serviceWorkerPrefix = 'BikeTag Service Worker :: '
				console.log(serviceWorkerPrefix + '${serviceWorkerLoadedMessage}');

				self.addEventListener('push', ev => {
					const data = ev.data.json();
					console.log(serviceWorkerPrefix + 'Recieved push from ${subdomain}.${host}', data);
					self.registration.showNotification(data.title, {
						body: data.message,
						icon: '${host}/public/favicon.ico'
					});
				});
			})()`)
        }

        const sendSubscribeJS = (req, res) => {
            const { host, subdomain } = res.locals
            const serviceWorkerRegisteringMessage =
                this.config.notifications.messages.serviceWorkerRegistering ??
                `registering service worker for ${subdomain}.${host}`
            const serviceWorkerRegisteredMessage =
                this.config.notifications.messages.serviceWorkerRegistered ??
                `registered service worker for ${subdomain}.${host}`

            res.set('content-type', 'text/javascript')

            return res.send(`
			(() => {
				const publicVapidKey = '${this.config.notifications.vapid.publicKey}'
				const serviceWorkerPrefix = 'BikeTag Service Worker :: '
				
				const urlBase64ToUint8Array = (base64String) => {
					var padding = '='.repeat((4 - base64String.length % 4) % 4);
					var base64 = (base64String + padding)
						.replace(/\-/g, '+')
						.replace(/_/g, '/');
				
					var rawData = window.atob(base64);
					var outputArray = new Uint8Array(rawData.length);
				
					for (var i = 0; i < rawData.length; ++i) {
						outputArray[i] = rawData.charCodeAt(i);
					}
					return outputArray;
				}

				async function run() {
					console.log(serviceWorkerPrefix + 'registering worker.js file from host ${subdomain}.${host}');
					const registration = await navigator.serviceWorker.register('/worker.js', {scope: '/'});
					console.log(serviceWorkerPrefix + '${serviceWorkerRegisteredMessage}');
				
					console.log(serviceWorkerPrefix + 'registering push');
					const subscription = await registration.pushManager.
					subscribe({
						userVisibleOnly: true,
						applicationServerKey: urlBase64ToUint8Array(publicVapidKey)
					});
					console.log(serviceWorkerPrefix + 'registered push');
				
					console.log(serviceWorkerPrefix + 'sending push');
					await fetch('/subscribe', {
						method: 'POST',
						body: JSON.stringify(subscription),
						headers: {
							'content-type': 'application/json'
						}
					});
					console.log(serviceWorkerPrefix + 'sent push');
				}

				if ('serviceWorker' in navigator) {
					console.log(serviceWorkerPrefix + '${serviceWorkerRegisteringMessage}');
				
					run().catch((error) => {
						if (error) console.error(error)
					})
				}
			})()`)
        }

        this.route('/subscribe', subscribeToNotifications, 'post')
        this.route('/js/subscribe.js', sendSubscribeJS, 'get')
        this.route('/js/worker.js', sendWorkerJS, 'get')

        /// TODO: Set this for all subdomains
        webpush.setVapidDetails(
            `mailto:${this.config.author.email}`,
            this.config.notifications.vapid.publicKey,
            this.config.notifications.vapid.privateKey,
        )

        this.notifications = {
            webpush,
            sendNotification: (subdmain, title, message) => {},
        }
        this.log.info('📌 Browser notifications have been enabled', this.config.notifications)
    }
}

module.exports = InitNotifications
module.exports.module = moduleName
module.exports.description =
    'Subscribes users to browser notifications and sends notifications to subscribers'
module.exports.defaults = false
module.exports.version = '0.0.1'
