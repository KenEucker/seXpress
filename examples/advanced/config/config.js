module.exports = {
    name: 'Advanced Application',
    port: 80,

    rendering: {
        overrideViewEngine: 'liquid',
	},
	
	login: true,
	authentication: true,

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

    // ssl: {
    // 	"strategy": "letsencrypt",
    // 	"passphrase": "myapppasphrase"
    // }
}
