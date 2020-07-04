const sexpress = require("..")
const app = sexpress('')

if (!module.parent) {
	app.run(() => {
		console.log("sexy!")
	})
}
