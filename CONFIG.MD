# seXpress configuration files

seXpress uses [clobfig](https://github.com/KenEucker/clobfig), a configurator library, to compile it's runtime configuration options. To add or modify options . More information about ways to add/modify the configuration can be found in the [clobfig documentation](https://github.com/KenEucker/clobfig).

# seXpress configuration options

When configuring your applicationg alongside the seXpress defaults, it is important to be aware of the following options. These options are used by the seXpress core library and are not attributed to any individual module.

## version (string)
| The version of the application

The version string to use when referencing the application in API strings and other software level variables.

## name (string)
| The name of the application

The name to use when referencing the application in API strings and other software level variables.

## author (string)
| The name/email address of the author of the application

The title to use when referencing the application in API strings and other software level variables.

## secret (string)
| The secret of the application

The default secret to use when securing the application with APIs and internal encryption schemes.

## description (string)
| The description of the application [optional:random]

The description to use when defining the application or publishing the application as a module.

## host (string)
| The hostname of the server where the application is recieving requests

The hostname is used to determine the subdomain of the incoming request as well as for constructing links internal to the site.

## title (string) 
| The title of the application [optional:random]

The title to use when referencing the application in API strings and other software level variables.

## defaults (object)
| Defaults for each subdomain [optional]

The defaults object is a special object in that it's contents are copied to all preconfigured subdomains in the subdomains configuration option.

## port (option)
| The title of the application [optional:80]

The title to use when referencing the application in API strings and other software level variables.

## generate (option) [optional:false]
| The generator options for the application

If defined (true or object with flags/vars), the generate options will be passed to the generate module, if enabled, to download source and template files from external repositories. This option is useful when creating deploy branches.

## subdomains (option)
| An object of named subdomain configurations [optional]

The list of subdomains configurations to use with the applications templates and controllers.

## folders (object)
| An object of named folders and their absolute paths [optional]

These are the main application folders defined with absolute paths from the root of the application. These should only be overloaded from the defaults with extreme caution. Clobfig will set the root to the application and then each of the folders listed below will match this pattern (/[.*]Folder/) to the name of the folder (for the most part).

	appFolder (/)
	configFolder (/config)
	contentFolder (/public/content)
	controllersFolder (/controllers)
	middlewaresFolder (*/middleware)
	publicFolder (/public)
	sslFolder (/config/ssl)
	srcFolder (/src)
	templatesFolder (/templates)
	viewsFolder (/controllers/views)

# seXpress module configurations

Each module within seXpress is initialized with it's own named option in the application config. The following options are examples of module configurations used to modify the functionality of the application. Not all available flags and variables will be defined here, as some pertain to private runtime values and the packages used by the module. All options defined here should work regardless of the version of the module as long as the major and minor version match the core major and minor version.

## api
| The api configuration

* apiFilename - the name of the api file that is available in the /public/js folder. [defaults to the name of the appication]

## authentication
| The authentication (first and third party) configuration including authentication strategies for supported authentication strategies using PassportJS

* credentials - the default credentials to use for all authentication strategies, if not explicitely set in the scheme.
* credentials.username - the default username to use for all authentication strategies, if not explicitely set in the scheme.
* credentials.password - the default password to use for all authentication strategies, if not explicitely set in the scheme.
* secret - the default secret to use for all authentication strategies, if not explicitely set in the scheme.
* propogate - whether or not logins to the main host should be sent to all configured subdomains to be logged in there as well.
* passport - the PassportJS configuration options (https://passportjs.com/docs)
* passport.session - the PassportJS session configuration options (https://passportjs.com/docs)

### authentication strategies are defined under this option (example below)
* authentication.imgur - the imgur authentication strategy options.
* authentication.imgur.imgurApiClientID - the imgur client ID to use when setting up the authentication imgur strategy.
* authentication.imgur.imgurApiClientSecret - the imgur client secret to use when setting up the authentication imgur strategy.
* authentication.imgur.imgurEmailAddress - the email address to use to use when setting up the authentication imgur strategy.

## cache
| The caching configuration
## compilation
| The compilation and source code configuration
## config (ui)
| The config ui configuration
## database
| The database connectors configuration
## debug
| The debug state

This option is a boolean only, unlike every other option this value can only be evaluated as true or false (or in the event that you want to isolate debugging messages to a specific module -- use the name of the module here).

## docs
| The api documentation configuration
## errors
| The error handling and error pages configuration
## export
| The export configuration
## generate
| The generate from source and template projects configuration
## hooks
| The webhooks configuration
## info
| The info configuration
## logging
| The logging (internal and external) configuration
## login
| The login configuration used in conjunction with the authentication configuration
## package
| The package configuration for packaging the application as a module
## rendering
| The rendering configuration
## robots
| The configuration for machine to machine communication that is non-user
## roles
| The application roles and permissions configuration
## routing
| The routing configuration options (not to be confused with routes)
## security
| The security policy and restrictions configuration
## session
| The serverside session configuration
## ssl
| The ssl configuration for use with autogenerated or preinstalled certificates
## static
| The configuration for defining the folders to be statically served by the application
## templating
| The templating configuration
## test
| The testing configuration

