const jwt_encode = require('jwt-encode');

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

module.exports = { generateJwtToken };

