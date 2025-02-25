const jwt_encode = require('jwt-encode');
const jwt = require('jsonwebtoken');

/**
 * Generates a JWT (JSON Web Token) with the provided payload data and configuration
 * 
 * @param {Object} data - The payload data to be encoded in the token
 * @param {string} issuer - The issuer of the token (typically your domain)
 * @param {string} secret - The secret key used to sign the token
 * @param {number} expiresIn - Token expiration time in seconds
 * @returns {string} The generated JWT token
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
    const payload = {
      data,
      iss: issuer,
      exp: Math.floor(Date.now() / 1000) + (expiresIn),
      iat: Math.floor(Date.now() / 1000)
    };

    return jwt_encode(payload, secret);
};

/**
 * Decodes and verifies a JWT token
 * 
 * @param {string} token - The JWT token to decode
 * @param {string} secret - The secret key used to verify the token's signature
 * @returns {Object} The verified and decoded token payload containing:
 *   - data: The custom payload data
 *   - iss: The token issuer
 *   - exp: The expiration timestamp
 *   - iat: The issued at timestamp
 * 
 * @throws {Error} If the token is invalid, expired, or has been tampered with
 * 
 * @example
 * try {
 *   const decodedToken = decodeJwtToken('your.jwt.token', 'your-secret-key');
 *   console.log(decodedToken.data); // Access the custom payload data
 *   console.log(decodedToken.iss); // Access the issuer
 * } catch (error) {
 *   console.error('Token verification failed:', error.message);
 * }
 */
const decodeJwtToken = (token, secret) => {
    try {
        return jwt.verify(token, secret);
    } catch (error) {
        throw new Error(`Failed to decode token: ${error.message}`);
    }
};

module.exports = { generateJwtToken, decodeJwtToken };

