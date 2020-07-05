# sexpress

A sexy wrapper around express for multitenant websites

sexpress provides a series of modules that can be turned on or off depending on the configuration set. In addition to this simple architecture, content editing and configuring can be done entirely via the codebase on GitHub. sexpress was built as an evolution of a modular webserver project that I had used on previous websites. I started the sexpress project after feeling like I had a solution that I could replace all previous solutions with for my websites. Enjoy!

## What is s\*e\*x\*y software?

- Simple
- Elegant
- X (Configurable)
- YOURS

It's easy to use, all inclusive, configurable by using JSON files, and it's yours to use for whatever you want.

## Getting started

Using Sexpress is even more simple than running express, as is the point.

```
const Sexpress = require("sexpress")
const sexpress = new Sexpress()
sexpress.run()

```

The above code will use all configuration set in the config/ folder. More on the configuration later.
