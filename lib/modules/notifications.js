/// Begin with the module name
const moduleName = 'notifications'

/// Name the module init method which is used in logging
function InitNotifications(initial, notificationsOpts = {}) {
    this.config.notifications = this.getCoreOpts(moduleName, notificationsOpts, initial)

    if (this.config.notifications.enabled) {
		const webpush = require('web-push');

		this.config.notifications = this.config.notifications || { enabled: true }
		this.config.notifications.vapid = this.config.notifications.vapid || {}
		this.config.notifications.gcmApikey = this.config.notifications.gcmApikey ?? this.config.authentication.google.googleApiKey

		if (!!this.config.notifications.vapid.publicKey && !!this.config.notifications.vapid.privateKey) {
			/// TODO: (per domain?)
			// VAPID keys should be generated only once. 
			const vapidKeys = webpush.generateVAPIDKeys()
			
			this.config.notifications.vapid.publicKey = vapidKeys.publicKey
			this.config.notifications.vapid.privateKey = vapidKeys.privateKey

			this.log.info('VAPID Keys generated', {vapidKeys})
		}

		if (this.config.notifications.gcmApikey) {
			webpush.setGCMAPIKey(this.config.notifications.gcmApikey)
		}

		const subscribeToNotifications = (req, res) => {
			const { host, subdomain } = res.locals
			const subscription = req.body
			res.status(201).json({})
			const payload = JSON.stringify({ title: 'Subscribed!', message: `You have been subscribed to notifications from ${subdomain ? `${subdomain}.` : ''}${host}` })
		  
			this.log.info('browser user subscribed to notifications', {subscription})
		  
			webpush.sendNotification(subscription, payload).catch(error => {
			  this.log.error(error.stack)
			})
		  }

		  const sendWorkerJS = (req, res) => {
				const { host, subdomain } = res.locals

				return res.send(`
				const serviceWorkerPrefix = 'BikeTag Service Worker :: '
				console.log(serviceWorkerPrefix + loaded The BikeTag-${subdomain} service worker from ${host}!');

				self.addEventListener('push', ev => {
					const data = ev.data.json();
					console.log(serviceWorkerPrefix + 'Got push from BikeTag ${subdomain}', data);
					self.registration.showNotification(data.title, {
						body: data.message,
						icon: '${host}/public/favicon.ico'
					});
				});
			  `)
		  }

		  const sendSubscribeJS = (req, res) => {
			const { host, subdomain } = res.locals

			return res.send(`
				const publicVapidKey = '${this.config.notifications.vapid.publicKey}'
				
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
					const serviceWorkerPrefix = 'BikeTag Service Worker :: '
					console.log(serviceWorkerPrefix + 'registering worker.js file from host ${host}');
					const registration = await navigator.serviceWorker.register('/worker.js', {scope: '/'});
					console.log(serviceWorkerPrefix + 'registered service worker for BikeTag ${subdomain}');
				
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
					console.log(serviceWorkerPrefix + 'registering service worker');
				
					run().catch(error => console.error(error));
				}
			`)
		  }

		this.route('/subscribe', subscribeToNotifications, 'post')
		this.route('/subscribe.js', sendSubscribeJS, 'get')
		this.route('/worker.js', sendWorkerJS, 'get')
		
		/// TODO: Set this for all subdomains
		webpush.setVapidDetails(
			`mailto:${this.config.author.email}`,
			this.config.notifications.vapid.publicKey,
			this.config.notifications.vapid.privateKey
		)

		this.notifications = {
			webpush,
			sendNotification: (subdmain, title, message) => {

			}
		}
    }
}

module.exports = InitNotifications
module.exports.module = moduleName
module.exports.description = 'Subscribes users to browser notifications and sends notifications to subscribers'
module.exports.defaults = false
module.exports.version = '0.0.1'
