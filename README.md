# sexpress

A configurable framework built around express for multitenant web applications.

sexpress provides a series of modules that can be turned on or off depending on the configuration set. In addition to this simple architecture, content editing and configuring can be done entirely via the codebase on GitHub. sexpress was built as an evolution of a modular webserver project that I had used on previous websites. I started the sexpress project after feeling like I had a solution that I could replace all previous solutions with for my websites. Enjoy!

## What is s\*e\*x\*y software?

-   Simple
-   Elegant
-   X (Configurable)
-   YOURS

It's easy to use, all inclusive, configurable by using JSON files, and it's yours to use for whatever you want.

## Getting started

Using Sexpress is even more simple than running express, as is the point.

```
const sexpress = require("sexpress")()
sexpress.run()
```

## Configuration

Sexpress can be configured by values in the package.json, a single config.json file in the config/ folder, or a set of files matching [*config.js, *.json] contained within the config/ folder. This is accomplished by using the package [clobfig](https://www.npmjs.com/package/clobfig).

A simple example configuration is below. With this configuration, sexpress will serve the index file located in templates/index/ folder and provide the data `{ meta: { title: "minimal" } }` upon render. (index.html or index.ejs by default)

```
{
    "subdomains": {
        "index": {
            "meta": {
                "title": "Minimal"
            }
        }
    }
}
```

In the tempalates/index folder, using the example config above, you might have the following index.ejs file:

```
<html>
	<head>
		<title><%= page.meta.title %></title>
	</head>
	<body>
		<p>Hello, world!</p>
	</body>
</html>
```

Also, in the same folder, you may have an index.scss file:

```
body {
	margin: auto;

	p {
		padding: 10em;
	}
}
```

Finally, when running sexpress, if you open up your browser to http://localhost, you should get the following response:

```
<html>
	<head>
		<title>Minimal</title>
		<style type="text/css" nonce>
			body {
				margin: auto;
			}

			body p {
				padding: 10em;
			}
		</style>
	</head>
	<body>
		<p>Hello, world!</p>
	</body>
</html>
```

### For more examples on how to configure and run sexpress applications, see the starter project [sexpress-starter](https://www.npmjs.com/package/sexpress-starter)

## Notes

This library is LARGE. Currently, there are 23 modules and 1 middlewares included in this project for the entire featureset of sexpress applications. Future development includes a dynamic mode option and the ability to package and deploy subsets of these modules and middlewares so that you only download the dependencies you are using.

Active development on this project will make all versions prior to 0.9.0 unstable and constantly shifting in use.
