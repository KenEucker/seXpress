const Sexpress = require("./lib/sexpress")
const sexpress = new Sexpress()

if (!module.parent) {
	sexpress.run(() => {
		console.log("sexy!")
	})
}
