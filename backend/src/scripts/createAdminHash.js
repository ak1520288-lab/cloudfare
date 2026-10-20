const crypto = require('node:crypto');
const { promisify } = require('node:util');

const scrypt = promisify(crypto.scrypt);

function readHiddenPassword() {
  if (!process.stdin.isTTY || !process.stdin.setRawMode) {
    return Promise.reject(new Error('Run this command in an interactive terminal.'));
  }

  return new Promise((resolve, reject) => {
    const input = process.stdin;
    let password = '';

    process.stdout.write('Choose an admin password (minimum 12 characters): ');
    input.setRawMode(true);
    input.resume();
    input.setEncoding('utf8');

    function cleanup() {
      input.removeListener('data', onData);
      input.setRawMode(false);
      input.pause();
      process.stdout.write('\n');
    }

    function onData(character) {
      if (character === '\u0003') {
        cleanup();
        reject(new Error('Password generation cancelled.'));
        return;
      }

      if (character === '\r' || character === '\n') {
        cleanup();
        resolve(password);
        return;
      }

      if (character === '\u007f' || character === '\b') {
        password = password.slice(0, -1);
        return;
      }

      if (character >= ' ' && character !== '\u007f') {
        password += character;
      }
    }

    input.on('data', onData);
  });
}

async function main() {
  const password = await readHiddenPassword();
  if (password.length < 12) {
    throw new Error('Password must be at least 12 characters long.');
  }

  const salt = crypto.randomBytes(16);
  const derivedKey = await scrypt(password, salt, 64, {
    N: 32768,
    r: 8,
    p: 1,
    maxmem: 64 * 1024 * 1024,
  });

  process.stdout.write(`ADMIN_PASSWORD_HASH=scrypt$${salt.toString('hex')}$${derivedKey.toString('hex')}\n`);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exitCode = 1;
});
