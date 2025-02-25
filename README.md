# jawty

A simple and lightweight JWT (JSON Web Token) generator for Node.js applications with payload encryption.

## Features

- Generate JWT tokens with standard claims (iss, exp, iat)
- AES-256-GCM encryption for payload data
- Secure token verification and payload decryption
- Built on standard Node.js crypto module

## Installation

Install the package using npm:

```bash
npm install jawty
```

## Usage

First, require the package in your code:

```javascript
const { generateJwtToken, decodeJwtToken } = require('jawty');
```

### Generating a JWT Token

The `generateJwtToken` function takes four parameters:

- `data` (Object): The payload data to be encrypted and encoded in the token
- `issuer` (String): The issuer of the token (typically your domain)
- `secret` (String): The secret key used to sign the token and encrypt the payload
- `expiresIn` (Number): Token expiration time in seconds

Example:

```javascript
const payload = {
    name: "John Doe",
    email: "john.doe@example.com"
};

const jwtToken = generateJwtToken(
    payload,
    "https://example.com",
    "your-secret-key",
    3600 // Expires in 1 hour
);

console.log(jwtToken);
```

### Verifying and Decoding Tokens

The `decodeJwtToken` function verifies the token signature and decrypts its payload in one step:

```javascript
try {
    const decodedToken = decodeJwtToken(jwtToken, 'your-secret-key');
    console.log(decodedToken.data);    // The decrypted payload data
    console.log(decodedToken.iss);     // The issuer
    console.log(decodedToken.exp);     // Expiration timestamp
    console.log(decodedToken.iat);     // Issued at timestamp
} catch (error) {
    console.error('Token verification failed:', error.message);
}
```

This method ensures:
- The token has a valid signature
- The token hasn't been tampered with
- The token hasn't expired
- The payload can be decrypted with the provided secret

The function will throw an error if:
- The token's signature is invalid
- The token has expired
- The token is malformed
- The payload cannot be decrypted (wrong secret key or corrupted data)

### Token Structure

The generated token includes:
- Encrypted custom payload data (using AES-256-GCM)
- Issuer (`iss`)
- Expiration time (`exp`)
- Issued at time (`iat`)

### Security Features

1. **Payload Encryption**: All payload data is encrypted using AES-256-GCM
   - Each token uses a unique Initialization Vector (IV)
   - Includes authentication tag to verify data integrity
   - Secret key is hashed using SHA-256

2. **Token Security**:
   - Signature verification ensures token authenticity
   - Expiration time prevents token reuse
   - Encrypted payload protects sensitive data

## Security Best Practices

1. Always use a strong, unique secret key (at least 32 characters)
2. Store secret keys securely (e.g., environment variables)
3. Set appropriate expiration times
4. Always verify tokens before trusting their contents
5. Rotate secret keys periodically
6. Use HTTPS for token transmission

## License

ISC

## Author

Tom Tarpey
