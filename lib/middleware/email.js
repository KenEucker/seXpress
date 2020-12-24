class email {
    constructor(emailOpts = {}) {
        if (typeof emailOpts === 'boolean') {
            emailOpts = {
                enabled: emailOpts,
            }
        }

        if (emailOpts.enabled) {
            this.nodemailer = require('nodemailer')
        }
    }

    async sendEmail(opts, to, subject, text, callback, html, from) {
        const configEmailAddressIsSet = !!opts.email.emailAccountAddress
        const configEmailHostIsSet = !!opts.email.emailAccountHost
        const configEmailServiceIsSet = !!opts.email.emailService

        // Generate test SMTP service account from ethereal.email
        // Only needed if you don't have a real mail account for testing
        const auth = configEmailAddressIsSet
            ? {
                  user: opts.email.emailAccountAddress,
                  pass: opts.email.emailAccountPassword,
              }
            : await this.nodemailer.createTestAccount()
        const host = configEmailHostIsSet ? opts.email.emailAccountHost : 'smtp.ethereal.email'
        const port = configEmailHostIsSet ? opts.email.emailAccountPort : 587
        const secure = configEmailHostIsSet ? opts.email.emailAccountIsSecure : false
        const service = configEmailServiceIsSet ? opts.email.emailService : null

        const emailOpts = {
            from: !!from ? from : auth.user, // sender address
            to, // list of receivers
            subject, // Subject line
            text, // plain text body
            html, // html body
        }

        const transporterOpts = {
            auth,
        }

        if (configEmailServiceIsSet) {
            transporterOpts.service = service

            if (opts.authTokens) {
                const googleOpts = opts.authTokens.google.opts.google || {}

                transporterOpts.auth.user = undefined
                transporterOpts.auth.pass = undefined
                transporterOpts.auth.type = 'OAuth2'
                transporterOpts.auth.clientId = googleOpts.googleClientID
                transporterOpts.auth.clientSecret = googleOpts.googleClientSecret
                transporterOpts.auth.refreshToken = opts.authTokens.google.googleRefreshToken
                transporterOpts.auth.accessToken = opts.authTokens.google.googleAccessToken
            }

            switch (opts.email.emailService) {
                case 'google':
                    // transporterOpts.ignoreTLS = false
                    break
            }
        } else {
            // create reusable transporter object using the default SMTP transport
            transporterOpts.host = host
            transporterOpts.port = port
            transporterOpts.secure = secure // true for 465, false for other ports
            transporterOpts.auth = auth
        }
        const transporter = this.nodemailer.createTransport(transporterOpts)

        // send mail with defined transport object
        const info = await transporter.sendMail(emailOpts)

        return callback(info)
    }
}

module.exports = email
