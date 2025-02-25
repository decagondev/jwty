# jwty

A simple and lightweight JWT (JSON Web Token) generator for Node.js applications.

## Installation

Install the package using npm:

```bash
npm install jwty
```

## Usage

First, require the package in your code:

```javascript
const { generateJwtToken } = require('jwty');
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

### Token Structure

The generated token includes:
- Custom payload data
- Issuer (`iss`)
- Expiration time (`exp`)
- Issued at time (`iat`)

## License

ISC

## Author

Tom Tarpey
