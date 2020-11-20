module.exports = {
    appName: 'Advanced Application',
    port: 80,
    headless: true,
    overrideViewEngine: 'liquid',
    onlyLogErrors: false,

    api: {
        secureApiDocs: true,
        privateApis: ['admin'],
    },

    security: {
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
    },

    // ssl: {
    // 	"strategy": "letsencrypt",
    // 	"passphrase": "myapppasphrase"
    // }
}
