module.exports = {
    appName: 'Advanced Application',
    port: 80,
    headless: true,
    documentAPI: true,
    onlyLogErrors: false,
    privateApis: ['admin'],
    security: {
        enabled: true,
        schemes: [
        	{
        		name: 'local',
        		credentials: {
        			username: 'test',
        			password: 'test',
        		}
			},
			'bearer',
			'basic'
        ],
    },
}
