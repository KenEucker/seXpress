module.exports = {
    name: 'Advanced Application',
	port: 80,
	silent: true,
	host: 'advanced.local',
	
	middlewares: {
		redis: {
			enabled:true,
		},
	},
	ui: true,

    rendering: {
        overrideViewEngine: ['liquid', 'ejs'],
    },

    login: true,

    session: {
		// disableCookies: true,
        redis: {
            enabled: true,
        },
    },

    logging: {
        onlyLogErrors: false,
    },

    templating: {
        home: 'hello',
        headless: true,
    },

    api: {
        secureApiDocs: true,
        privateApis: ['admin'],
	},

    authentication: {
        enabled: true,
        schemes: [
            {
                name: 'local',
                credentials: {
                    username: 'test',
                    password: 'test',
                },
            },
            {
                name: 'jwt',
                credentials: {
                    secret: 'dawg',
                },
            },
            // 'basic'
        ],
        auth0: {
			auth0ClientID: 'dzhU3eF3t534okbV4oy10tvcTab6LVo0',
			auth0ClientSecret: 'ae-_ibEfTPb5gRhHXWZFxug3MkwG96zYmVULpzWmwt8imCokpylKDuoSzAbuKNKE',
			auth0ClientDomain: 'biketag.us.auth0.com',
        }

		// "imgur": {
		// }
    },

    ssl: {
        enabled: true,
        // strategy: 'greenlock',
        contentSecurityPolicy: {
            directives: {
                styleSrc: [`https://code.jquery.com/`, `https://cdn.jsdelivr.net/`],
                scriptSrc: [`https://code.jquery.com/`, `https://cdn.jsdelivr.net/`],
            },
        },
    },
}
