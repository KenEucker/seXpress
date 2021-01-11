# Our application's javascript API for both servers and clients
class Api

	constructor: (opts = {}) ->
		@specUrl = opts.specUrl ? '/api/swagger.json'
		@init()

	init: () ->
		# this activates CORS, if necessary
		SwaggerClient.http.withCredentials = true
		new SwaggerClient(@specUrl)
			.then(((swaggerClient) ->
				window.apiClient = swaggerClient
			), (reason) ->
				console.error 'failed to load the spec' + reason
				return
			)
	
	_callApiMethod: (method, args, api = 'default') -> 
		if window.apiClient?.apis
			window.apiClient.apis[api][method](args)
		else
			return new Promise(async (resolve) ->
				setTimeout ->
					resolve(@_callApiMethod(method, args, api))
				, 100

	yo: (yo) ->
		console.log "#{yo} dawg."
		return @_callApiMethod('post_v1_yo__yo_')
			.then ((yoResult) ->
				console.log yoResult.obj
				document.getElementsByTagName('p').item(0).innerText = yoResult.obj.yo
				return
			), (reason) ->
				console.error 'failed on API call ' + reason
				return

module.exports = new Api()
