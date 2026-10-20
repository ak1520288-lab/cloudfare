require('dotenv').config();

const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

async function main() {
  const username = String(process.env.USERNAME || '').trim();
  const password = process.env.PASSWORD || '';

  if (!/^[a-zA-Z0-9._-]{1,64}$/.test(username)) {
    throw new Error('Legacy USERNAME must contain only letters, numbers, dots, underscores, or hyphens.');
  }
  if (password.length < 12 || password.length > 1024) {
    throw new Error(
      'Legacy PASSWORD must be 12–1024 characters. Use "npm run create-admin-hash" to set a new password.',
    );
  }

  const salt = crypto.randomBytes(16);
  const hash = await scrypt(password, salt, 64, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });

  process.stdout.write(`ADMIN_USERNAME=${username}\n`);
  process.stdout.write(`ADMIN_PASSWORD_HASH=scrypt$${salt.toString('hex')}$${hash.toString('hex')}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
