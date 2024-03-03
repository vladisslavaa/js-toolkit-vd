const crypto = require('crypto');

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem'
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem'
  }
});

// Encrypt and decrypt a message using RSA
const message = 'Hello, RSA!';
const encryptedMessage = crypto.publicEncrypt(publicKey, Buffer.from(message, 'utf8')).toString('base64');
const decryptedMessage = crypto.privateDecrypt(privateKey, Buffer.from(encryptedMessage, 'base64')).toString('utf8');

console.log('Original Message:', message);
console.log('Encrypted Message:', encryptedMessage);
console.log('Decrypted Message:', decryptedMessage);

// Sign and verify the integrity of the message using RSA
const sign = crypto.createSign('RSA-SHA256');
sign.update(message);
const signature = sign.sign(privateKey, 'base64');

const verify = crypto.createVerify('RSA-SHA256');
verify.update(message);
const isVerified = verify.verify(publicKey, signature, 'base64');

console.log('Signature:', signature);
console.log('Is Message Verified?', isVerified);
