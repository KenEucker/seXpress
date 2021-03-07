module.exports = {
    name: 'Backend',
	port: 8080,
	silent: true,
	// host: 'backend.local',
	middlewares: {
		redis: {
			enabled:true,
		},
	
		portainer: {
			enabled: true,
			email: 'keneucker@gmail.com',
		},
	},
}
