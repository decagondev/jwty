const jwt_encode = require('jwt-encode');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

/**
 * Encrypts data using AES-256-GCM
 * @private
 * @param {Object} data - Data to encrypt
 * @param {string} secret - Secret key for encryption
 * @returns {Object} - Encrypted data with IV and auth tag
 */
const encryptData = (data, secret) => {
    // Create a key from the secret using SHA256
    const key = crypto.createHash('sha256').update(secret).digest();
    // Generate a random IV
    const iv = crypto.randomBytes(12);
    // Create cipher
    const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
    
    // Encrypt the data
    const stringData = JSON.stringify(data);
    const encrypted = Buffer.concat([
        cipher.update(stringData, 'utf8'),
        cipher.final()
    ]);
    
    // Get auth tag
    const authTag = cipher.getAuthTag();
    
    return {
        encrypted: encrypted.toString('base64'),
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64')
    };
};

/**
 * Decrypts data using AES-256-GCM
 * @private
 * @param {Object} encryptedData - Encrypted data object with IV and auth tag
 * @param {string} secret - Secret key for decryption
 * @returns {Object} - Decrypted data
 */
const decryptData = (encryptedData, secret) => {
    // Create a key from the secret using SHA256
    const key = crypto.createHash('sha256').update(secret).digest();
    // Convert base64 strings back to buffers
    const iv = Buffer.from(encryptedData.iv, 'base64');
    const encrypted = Buffer.from(encryptedData.encrypted, 'base64');
    const authTag = Buffer.from(encryptedData.authTag, 'base64');
    
    // Create decipher
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(authTag);
    
    // Decrypt the data
    const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
    ]);
    
    return JSON.parse(decrypted.toString('utf8'));
};

/**
 * Generates a JWT (JSON Web Token) with encrypted payload data
 * 
 * @param {Object} data - The payload data to be encrypted and encoded in the token
 * @param {string} issuer - The issuer of the token (typically your domain)
 * @param {string} secret - The secret key used to sign the token and encrypt the payload
 * @param {number} expiresIn - Token expiration time in seconds
 * @returns {string} The generated JWT token with encrypted payload
 * 
 * @example
 * const token = generateJwtToken(
 *   { name: "John Doe", email: "john@example.com" },
 *   "https://example.com",
 *   "your-secret-key",
 *   3600 // 1 hour
 * );
 */
const generateJwtToken = (data, issuer, secret, expiresIn) => {
    // Encrypt the data
    const encryptedData = encryptData(data, secret);
    
    const payload = {
        data: encryptedData, // Store encrypted data instead of raw data
        iss: issuer,
        exp: Math.floor(Date.now() / 1000) + (expiresIn),
        iat: Math.floor(Date.now() / 1000)
    };

    return jwt_encode(payload, secret);
};

/**
 * Decodes and verifies a JWT token, and decrypts its payload
 * 
 * @param {string} token - The JWT token to decode
 * @param {string} secret - The secret key used to verify the token's signature and decrypt the payload
 * @returns {Object} The verified and decrypted token payload containing:
 *   - data: The decrypted custom payload data
 *   - iss: The token issuer
 *   - exp: The expiration timestamp
 *   - iat: The issued at timestamp
 * 
 * @throws {Error} If the token is invalid, expired, has been tampered with, or cannot be decrypted
 * 
 * @example
 * try {
 *   const decodedToken = decodeJwtToken('your.jwt.token', 'your-secret-key');
 *   console.log(decodedToken.data); // Access the decrypted payload data
 *   console.log(decodedToken.iss); // Access the issuer
 * } catch (error) {
 *   console.error('Token verification failed:', error.message);
 * }
 */
const decodeJwtToken = (token, secret) => {
    try {
        const verified = jwt.verify(token, secret);
        // Decrypt the data payload
        const decryptedData = decryptData(verified.data, secret);
        // Return the token with decrypted data
        return {
            ...verified,
            data: decryptedData
        };
    } catch (error) {
        if (error.message.includes('decryption failed')) {
            throw new Error('Failed to decrypt token payload: Invalid secret key or corrupted data');
        }
        throw new Error(`Failed to decode token: ${error.message}`);
    }
};

module.exports = { generateJwtToken, decodeJwtToken };

