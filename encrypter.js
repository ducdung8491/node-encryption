const crypto = require('crypto')

const base64Encode = (str) => {
    return Buffer.from(str, 'utf8').toString('base64')
}

const base64Decode = (str) => {
    return Buffer.from(str, 'base64').toString('utf8')
}

class Encrypter {
    constructor(key) {
        this.key = key
        this.cipher = 'aes-256-cbc'
    }
    encrypt(plainText) {
        let iv = crypto.randomBytes(8).toString('hex')
        const cipher = crypto.createCipheriv(this.cipher, this.key, iv)
        const value = cipher.update(plainText, 'utf8', 'base64') + cipher.final('base64')
        const mac = this.hash(iv = base64Encode(iv), value)
        const raw = JSON.stringify({ iv, value, mac })
        return base64Encode(raw)
    }
    decrypt(cipherText) {
        const payload = JSON.parse(base64Decode(cipherText))
        const mac = this.hash(payload.iv, payload.value)
        if (payload.mac !== mac) {
            throw new Error('The MAC is invalid')
        }
        let iv = base64Decode(payload.iv)
        const decipher = crypto.createDecipheriv(this.cipher, this.key, iv)
        return decipher.update(payload.value, 'base64', 'utf8') + decipher.final('utf8')
    }
    hash(iv, value) {
        return crypto.createHmac('sha256', this.key).update(iv + value).digest('hex')
    }
}

const generateKey = () => {
    return crypto.randomBytes(32)
}

const newCrypt = (key) => {
    if (!key) key = generateKey()
    return new Encrypter(key)
}

module.exports = {
    Encrypter,
    generateKey,
    newCrypt
}
