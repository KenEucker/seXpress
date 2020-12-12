module.exports = {
    name: 'Advanced Application',
	port: 80,
	silent: true,
	
	ui: true,

    rendering: {
        overrideViewEngine: ['liquid', 'ejs'],
    },

    login: true,
    authentication: true,

    session: {
        redis: {
            // enabled: true,
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
        // google: {

        // }

		"imgur": {
			"imgurClientID": "a404f3d0c94ee79",
			"imgurAuthorization": "Client-ID a404f3d0c94ee79",
			"imgurClientSecret": "310744f351ff8d9f11d2d84726497908823c5013",
			"imgurEmailAddress": "pdxbiketag@gmail.com"
		}
    },

    ssl: {
        enabled: true,
        strategy: 'greenlock',
        contentSecurityPolicy: {
            directives: {
                styleSrc: [`https://code.jquery.com/`, `https://cdn.jsdelivr.net/`],
                scriptSrc: [`https://code.jquery.com/`, `https://cdn.jsdelivr.net/`],
            },
        },
    },
}
