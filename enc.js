const crypto = require('crypto');

// Encryption key (use a secure, random key)
const encryptionKey = '12345678123456781234567812345678'; // 32-byte key
const algorithm = 'aes-256-cbc'; // Encryption algorithm
const iv = crypto.randomBytes(16); // Initialization vector

// Function to encrypt the description
function encryptDescription(description) {
    const cipher = crypto.createCipheriv(algorithm, Buffer.from(encryptionKey), iv);
    let encrypted = cipher.update(description, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return {
        encryptedData: encrypted,
        iv: iv.toString('hex'),
    };
}

// Function to decrypt the description
function decryptDescription(encryptedData, iv) {
    const decipher = crypto.createDecipheriv(algorithm, Buffer.from(encryptionKey), Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Example usage
const data = encryptDescription('This is a sensitive description');
console.log('Encrypted:', data);

const decrypted = decryptDescription(data.encryptedData, data.iv);
console.log('Decrypted:', decrypted);
