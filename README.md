# jawty

A simple and lightweight JWT (JSON Web Token) generator for Node.js applications.

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

- `data` (Object): The payload data to be encoded in the token
- `issuer` (String): The issuer of the token (typically your domain)
- `secret` (String): The secret key used to sign the token
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

The `decodeJwtToken` function verifies and decodes a token in one step:

```javascript
try {
    const decodedToken = decodeJwtToken(jwtToken, 'your-secret-key');
    console.log(decodedToken.data);    // The custom payload data
    console.log(decodedToken.iss);     // The issuer
    console.log(decodedToken.exp);     // Expiration timestamp
    console.log(decodedToken.iat);     // Issued at timestamp
} catch (error) {
    console.error('Token verification failed:', error.message);
}
```

This method ensures the token:
- Has a valid signature
- Hasn't been tampered with
- Hasn't expired

The function will throw an error if:
- The token's signature is invalid
- The token has expired
- The token is malformed

### Token Structure

The generated token includes:
- Custom payload data
- Issuer (`iss`)
- Expiration time (`exp`)
- Issued at time (`iat`)

## Security Best Practices

1. Always use a strong, unique secret key
2. Store secret keys securely (e.g., environment variables)
3. Set appropriate expiration times
4. Always verify tokens before trusting their contents
5. Never store sensitive information in the token payload

## License

ISC

## Author

Tom Tarpey
