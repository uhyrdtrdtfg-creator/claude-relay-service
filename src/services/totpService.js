/**
 * TOTP (Time-based One-Time Password) Service
 * 为管理员账户提供两因素认证功能
 */
const crypto = require('crypto')
const { authenticator } = require('otplib')
const QRCode = require('qrcode')
const config = require('../../config/config')
const logger = require('../utils/logger')

class TotpService {
  constructor() {
    // 加密相关常量（与 claudeAccountService 保持一致）
    this.ENCRYPTION_ALGORITHM = 'aes-256-cbc'
    this.ENCRYPTION_SALT = 'salt'

    // 缓存派生的加密密钥
    this._encryptionKeyCache = null

    // TOTP 配置
    this.issuer = 'Claude Relay Service'

    // 配置 otplib
    authenticator.options = {
      digits: 6,
      step: 30, // 30秒一个周期
      window: 1 // 允许前后各1个周期的容错
    }
  }

  /**
   * 生成 TOTP secret
   * @returns {string} Base32 编码的 secret
   */
  generateSecret() {
    return authenticator.generateSecret()
  }

  /**
   * 验证 TOTP 码
   * @param {string} secret - Base32 编码的 secret
   * @param {string} token - 用户输入的 6 位验证码
   * @returns {boolean} 验证是否通过
   */
  verifyToken(secret, token) {
    try {
      if (!secret || !token) {
        return false
      }

      // 移除空格和非数字字符
      const cleanToken = token.replace(/\s/g, '').replace(/\D/g, '')
      if (cleanToken.length !== 6) {
        return false
      }

      return authenticator.verify({ token: cleanToken, secret })
    } catch (error) {
      logger.error('TOTP verification error:', error)
      return false
    }
  }

  /**
   * 生成 QR 码 Data URL
   * @param {string} username - 用户名
   * @param {string} secret - Base32 编码的 secret
   * @returns {Promise<string>} QR 码的 Data URL
   */
  async generateQRCode(username, secret) {
    try {
      const otpauth = authenticator.keyuri(username, this.issuer, secret)
      const dataUrl = await QRCode.toDataURL(otpauth, {
        errorCorrectionLevel: 'M',
        type: 'image/png',
        width: 256,
        margin: 2
      })
      return dataUrl
    } catch (error) {
      logger.error('QR Code generation error:', error)
      throw new Error('Failed to generate QR code')
    }
  }

  /**
   * 生成 otpauth URI（用于手动输入）
   * @param {string} username - 用户名
   * @param {string} secret - Base32 编码的 secret
   * @returns {string} otpauth URI
   */
  generateOtpauthUri(username, secret) {
    return authenticator.keyuri(username, this.issuer, secret)
  }

  /**
   * 加密 TOTP secret
   * @param {string} secret - 明文 secret
   * @returns {string} 加密后的 secret
   */
  encryptSecret(secret) {
    if (!secret) {
      return ''
    }

    try {
      const key = this._generateEncryptionKey()
      const iv = crypto.randomBytes(16)

      const cipher = crypto.createCipheriv(this.ENCRYPTION_ALGORITHM, key, iv)
      let encrypted = cipher.update(secret, 'utf8', 'hex')
      encrypted += cipher.final('hex')

      // 将IV和加密数据一起返回，用:分隔
      return `${iv.toString('hex')}:${encrypted}`
    } catch (error) {
      logger.error('TOTP secret encryption error:', error)
      throw new Error('Failed to encrypt TOTP secret')
    }
  }

  /**
   * 解密 TOTP secret
   * @param {string} encryptedSecret - 加密的 secret
   * @returns {string} 解密后的 secret
   */
  decryptSecret(encryptedSecret) {
    if (!encryptedSecret) {
      return ''
    }

    try {
      // 检查是否是加密格式（包含IV）
      if (!encryptedSecret.includes(':')) {
        logger.warn('TOTP secret not in expected encrypted format')
        return encryptedSecret
      }

      const parts = encryptedSecret.split(':')
      if (parts.length !== 2) {
        logger.warn('TOTP secret format invalid')
        return encryptedSecret
      }

      const key = this._generateEncryptionKey()
      const iv = Buffer.from(parts[0], 'hex')
      const encrypted = parts[1]

      const decipher = crypto.createDecipheriv(this.ENCRYPTION_ALGORITHM, key, iv)
      let decrypted = decipher.update(encrypted, 'hex', 'utf8')
      decrypted += decipher.final('utf8')

      return decrypted
    } catch (error) {
      logger.error('TOTP secret decryption error:', error)
      throw new Error('Failed to decrypt TOTP secret')
    }
  }

  /**
   * 生成加密密钥（与 claudeAccountService 保持一致）
   * @returns {Buffer} 32字节密钥
   */
  _generateEncryptionKey() {
    if (!this._encryptionKeyCache) {
      this._encryptionKeyCache = crypto.scryptSync(
        config.security.encryptionKey,
        this.ENCRYPTION_SALT,
        32
      )
      logger.info('TOTP encryption key derived and cached')
    }
    return this._encryptionKeyCache
  }

  /**
   * 生成当前的 TOTP 码（用于测试）
   * @param {string} secret - Base32 编码的 secret
   * @returns {string} 6 位验证码
   */
  generateCurrentToken(secret) {
    try {
      return authenticator.generate(secret)
    } catch (error) {
      logger.error('TOTP token generation error:', error)
      return null
    }
  }
}

// 单例模式
const totpService = new TotpService()

module.exports = totpService
