const { generateJwtToken } = require('./index');

const jwtToken = generateJwtToken({
    name: "John Doe",
    email: "john.doe@example.com"
}, "https://example.com", "secret", 60 * 60);

console.log(jwtToken);