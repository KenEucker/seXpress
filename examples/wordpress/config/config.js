module.exports = {
    name: 'Advanced Application',
	port: 80,
	silent: true,
	host: 'advanced.local',
	
	middlewares: {
		redis: {
			enabled:true,
		},
	
		wordpress: {
			enabled: true,
		},
	},
	ui: true,

    rendering: {
        overrideViewEngine: ['liquid', 'ejs'],
    },

    login: true,

    session: {
		disableCookies: true,
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
        ],
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
