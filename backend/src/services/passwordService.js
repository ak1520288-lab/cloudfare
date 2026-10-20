const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

async function verifyPassword(password, saltHex, expectedHashHex) {
  const salt = Buffer.from(saltHex, 'hex');
  const expectedHash = Buffer.from(expectedHashHex, 'hex');
  const actualHash = await scrypt(password, salt, expectedHash.length, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  return crypto.timingSafeEqual(actualHash, expectedHash);
}

async function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const derivedKey = await scrypt(password, salt, 64, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });
  return {
    salt: salt.toString('hex'),
    hash: derivedKey.toString('hex'),
  };
}

module.exports = { hashPassword, verifyPassword };
