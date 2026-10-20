const test = require('node:test');
const assert = require('node:assert/strict');
const SecurityEvent = require('../models/SecurityEvent');
const User = require('../models/User');
const {
  collectionValidators,
  ensureCollectionValidators,
} = require('../validators');

test('security event schema validates enums and integer HTTP status codes', async () => {
  const validEvent = new SecurityEvent({
    category: 'auth',
    outcome: 'allowed',
    statusCode: 200,
  });
  await validEvent.validate();
  assert.equal(SecurityEvent.schema.options.timestamps.createdAt, true);

  const invalidCategory = new SecurityEvent({
    category: 'unknown',
    outcome: 'allowed',
  });
  await assert.rejects(invalidCategory.validate(), /category/);

  const invalidStatus = new SecurityEvent({
    category: 'auth',
    outcome: 'allowed',
    statusCode: 200.5,
  });
  await assert.rejects(invalidStatus.validate(), /statusCode/);
});

test('security event schema defines chronological and configured TTL indexes', () => {
  const indexes = SecurityEvent.schema.indexes();
  assert.ok(indexes.some(([fields]) => fields.createdAt === -1));
  assert.ok(indexes.some(([fields, options]) =>
    fields.createdAt === 1 && options.expireAfterSeconds === 30 * 86400,
  ));
});

test('user schema normalizes usernames, restricts public role, and hides password material', async () => {
  const user = new User({
    username: 'Viewer_01',
    passwordSalt: 'a'.repeat(32),
    passwordHash: 'b'.repeat(128),
    role: 'viewer',
  });
  await user.validate();
  assert.equal(user.username, 'viewer_01');
  assert.equal(User.schema.path('passwordSalt').options.select, false);
  assert.equal(User.schema.path('passwordHash').options.select, false);

  const invalidRole = new User({
    username: 'viewer_02',
    passwordSalt: 'a'.repeat(32),
    passwordHash: 'b'.repeat(128),
    role: 'admin',
  });
  await assert.rejects(invalidRole.validate(), /role/);

  const invalidPasswordHash = new User({
    username: 'viewer_03',
    passwordSalt: 'a'.repeat(32),
    passwordHash: 'plaintext-password',
    role: 'viewer',
  });
  await assert.rejects(invalidPasswordHash.validate(), /passwordHash/);
});

test('user schema enforces unique usernames with a database index', () => {
  assert.ok(User.schema.indexes().some(([fields, options]) =>
    fields.username === 1 && options.unique === true,
  ));
});

test('database validators cover required collections with strict rejection', async () => {
  const commands = [];
  const collectionInfo = {
    securityevents: { options: {} },
    users: { options: {} },
  };
  await ensureCollectionValidators({
    async command(command) {
      commands.push(command);
      collectionInfo[command.collMod].options = {
        validator: command.validator,
        validationLevel: command.validationLevel,
        validationAction: command.validationAction,
      };
      return { ok: 1 };
    },
    listCollections({ name }) {
      return { next: async () => collectionInfo[name] };
    },
    collection() {
      return { countDocuments: async () => 0 };
    },
  });

  assert.deepEqual(commands.map(({ collMod }) => collMod), [
    'securityevents',
    'securityevents',
    'users',
    'users',
  ]);
  for (const command of commands.filter(({ validationLevel }) => validationLevel === 'strict')) {
    assert.equal(command.validationAction, 'error');
    assert.equal(command.validator.$jsonSchema.additionalProperties, false);
  }
  const commandCount = commands.length;
  const results = await ensureCollectionValidators({
    command: async (command) => commands.push(command),
    listCollections({ name }) {
      return { next: async () => collectionInfo[name] };
    },
  });
  assert.equal(commands.length, commandCount);
  assert.ok(results.every(({ validationLevel, validationAction }) =>
    validationLevel === 'strict' && validationAction === 'error',
  ));
  assert.deepEqual(collectionValidators.users.$jsonSchema.properties.role.enum, ['viewer']);
  assert.deepEqual(
    collectionValidators.securityevents.$jsonSchema.properties.outcome.enum,
    ['allowed', 'blocked', 'warning'],
  );
});

test('database validation remains warning-only when existing documents do not match', async () => {
  const commands = [];
  const results = await ensureCollectionValidators({
    async command(command) {
      commands.push(command);
      return { ok: 1 };
    },
    listCollections({ name }) {
      return { next: async () => ({ name, options: {} }) };
    },
    collection(name) {
      return {
        countDocuments: async () => (name === 'securityevents' ? 3 : 0),
      };
    },
  });

  assert.equal(results[0].validationLevel, 'moderate');
  assert.equal(results[0].validationAction, 'warn');
  assert.equal(results[0].invalidDocuments, 3);
  assert.equal(commands.some((command) =>
    command.collMod === 'securityevents' && command.validationLevel === 'strict',
  ), false);
  assert.equal(commands.some((command) =>
    command.collMod === 'users' && command.validationLevel === 'strict',
  ), true);
});
