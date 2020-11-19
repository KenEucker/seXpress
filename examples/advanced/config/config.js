module.exports = {
    appName: 'Advanced Application',
    port: 80,
    headless: true,
    // secureApiDocs: true,
    onlyLogErrors: false,
    overrideViewEngine: 'liquid',
    privateApis: ['admin'],
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
