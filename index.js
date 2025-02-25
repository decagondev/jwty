const jwt_encode = require('jwt-encode');

const generateJwtToken = (data, issuer, secret, expiresIn) => {
    const payload = {
      data,
      iss: issuer,
      exp: Math.floor(Date.now() / 1000) + (expiresIn), // Token expires in 1 hour
      iat: Math.floor(Date.now() / 1000)
    };

    return jwt_encode(payload, secret);
};

module.exports = { generateJwtToken };

