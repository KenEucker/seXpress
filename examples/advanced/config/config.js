module.exports = {
    name: 'Advanced Application',
    port: 80,

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
