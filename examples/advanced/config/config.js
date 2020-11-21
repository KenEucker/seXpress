module.exports = {
    appName: 'Advanced Application',
    port: 80,

    rendering: {
        overrideViewEngine: 'liquid',
    },

    logging: {
        onlyLogErrors: false,
    },

    templating: {
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

    // ssl: {
    // 	"strategy": "letsencrypt",
    // 	"passphrase": "myapppasphrase"
    // }
}
