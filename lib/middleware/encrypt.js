class encryptObject {
    constructor() {
        this.crypto = require('crypto')
    }

    md5(text) {
        return this.crypto.createHash('md5').update(text).digest()
    }

    encrypt(secretKey = '', text) {
        try {
            text = typeof text !== 'string' ? JSON.stringify(text) : text

            secretKey = this.md5(secretKey)
            secretKey = Buffer.concat([secretKey, secretKey.slice(0, 8)]) // properly expand 3DES key from 128 bit to 192 bit

            const cipher = this.crypto.createCipheriv('des-ede3', secretKey, '')
            const encrypted = cipher.update(text, 'utf8', 'base64')

            return encrypted + cipher.final('base64')
        } catch (e) {
            /// swallow exception
            return null
        }
    }

    decrypt(secretKey = '', encryptedBase64) {
        try {
            secretKey = this.md5(secretKey)
            secretKey = Buffer.concat([secretKey, secretKey.slice(0, 8)]) // properly expand 3DES key from 128 bit to 192 bit
            const decipher = this.crypto.createDecipheriv('des-ede3', secretKey, '')
            let decrypted = decipher.update(encryptedBase64, 'base64')
            decrypted += decipher.final()

            const jsonObject = JSON.parse(decrypted)

            return jsonObject || decrypted
        } catch (e) {
            /// swallow exception
            return null
        }
    }
}

module.exports = encryptObject
