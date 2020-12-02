import * as advanced_applcation_api from '../../public/js/advanced_application-api.js'

export class AdvancedApi {
	apiClient: object

	constructor() {
		console.log('Awesome!', advanced_applcation_api)

		var specUrl = '/api/swagger.json' // data urls are OK too 'data:application/json;base64,abc...'
		advanced_applcation_api.http.withCredentials = true // this activates CORS, if necessary

		const apiClient = new advanced_applcation_api(specUrl)
			.then((swaggerClient) => {
				this.apiClient = swaggerClient
				console.log({swaggerClient})

				return {yo: "no"}
				// return this.apiClient.apis.default.post_v1_yo__yo_({yo: "Yo!"})
			}, (reason) => {
				console.error("failed to load the spec" + reason)
			})
			.then((yoResult) => {
				console.log(yoResult.obj)

				document.getElementsByTagName('p').item(0).innerText = yoResult.obj.yo
				// you may return more promises, if necessary
			}, (reason) => {
				console.error("failed on API call " + reason);
			})
	}
}

const instance = new AdvancedApi()
export { instance }


