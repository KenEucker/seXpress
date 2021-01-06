# Our application's javascript API for both servers and clients
class Api

	constructor: (opts = {}) ->
		@specUrl = opts.specUrl ? '/api/swagger.json'

	init: () ->
		# data urls are OK too 'data:application/json;base64,abc...'
		SwaggerClient.http.withCredentials = true
		# this activates CORS, if necessary
		new SwaggerClient(@specUrl).then(((swaggerClient) ->
			window.apiClient = swaggerClient
			window.apiClient.apis.default.post_v1_yo__yo_ yo: 'Yo!'
		), (reason) ->
			console.error 'failed to load the spec' + reason
			return
		).then ((yoResult) ->
			console.log yoResult.obj
			document.getElementsByTagName('p').item(0).innerText = yoResult.obj.yo
			# you may return more promises, if necessary
			return
		), (reason) ->
			console.error 'failed on API call ' + reason
			return

		yo: (yo) ->
			console.log "#{yo} dawg."

module.exports =
	Api
