/// Begin with the module name
const moduleName = 'database'

/// Name the module init method which is used in logging
function InitDatabase(initial, databaseOpts = {}) {
    this.config.database = this.getCoreOpts(moduleName, databaseOpts, initial)

    if (this.config.database.enabled) {
        switch (this.config.database.provider) {
            case 'supabase':
                this.config.supabase = this.config.supabase ?? {}
                this.config.supabase.POSTGRES_PASSWORD =
                    this.config.database.POSTGRES_PASSWORD ??
                    this.config.database.postgres_pass ??
                    ''
                this.config.supabase.JWT_SECRET =
                    this.config.database.JWT_SECRET ?? this.config.database.jwt_secret ?? ''
                this.config.supabase.SITE_URL =
                    this.config.database.SITE_URL ?? this.config.database.site_url ?? ''
                this.config.supabase.SMTP_HOST =
                    this.config.database.SMTP_HOST ??
                    this.config.database.smtp_host ??
                    'smtp.gmail.com'
                this.config.supabase.SMTP_SENDER_NAME =
                    this.config.database.SMTP_SENDER_NAME ??
                    this.config.database.smtp_sender_name ??
                    ''
                this.config.supabase.SMTP_PASS =
                    this.config.database.SMTP_PASS ?? this.config.database.smtp_pass ?? ''
                this.config.supabase.SMTP_USER =
                    this.config.database.SMTP_USER ?? this.config.database.smtp_user ?? ''
                this.config.supabase.SMTP_PORT =
                    this.config.database.SMTP_PORT ?? this.config.database.smtp_port ?? ''
                this.config.supabase.SMTP_ADMIN_EMAIL =
                    this.config.database.SMTP_ADMIN_EMAIL ?? this.config.database.smtp_email ?? ''
                break
            case 'sqlite':
            default:
                this.config.database.provider = 'sqlite'
                this.config.database.url = this.config.database.url ?? 'file:./data.db'
                break
			case 'gun':
				const Gun = require('gun');
				this.app.use(Gun.serve)

				this.hook('sexpress::start',
					async (server) => {
						Gun({ file: './db/data.json', web: server })
					})
				break
        }
    }
}

module.exports = InitDatabase
module.exports.module = moduleName
module.exports.description = 'Manages the connection to databases used across the application'
module.exports.defaults = false
module.exports.version = '0.0.1'
