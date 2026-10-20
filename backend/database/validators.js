const { isDeepStrictEqual } = require('node:util');

const numberTypes = ['int', 'long', 'double', 'decimal'];

const collectionValidators = {
  securityevents: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['category', 'outcome', 'createdAt'],
      additionalProperties: false,
      properties: {
        _id: { bsonType: 'objectId' },
        category: {
          bsonType: 'string',
          enum: ['proxy', 'rate_limit', 'waf', 'ip_block', 'auth', 'admin'],
        },
        outcome: { bsonType: 'string', enum: ['allowed', 'blocked', 'warning'] },
        method: { bsonType: 'string', maxLength: 12 },
        path: { bsonType: 'string', maxLength: 512 },
        ip: { bsonType: 'string', maxLength: 64 },
        statusCode: {
          bsonType: numberTypes,
          minimum: 100,
          maximum: 599,
          multipleOf: 1,
        },
        reason: { bsonType: 'string', maxLength: 240 },
        actor: { bsonType: 'string', maxLength: 64 },
        requestId: { bsonType: 'string', maxLength: 64 },
        durationMs: { bsonType: numberTypes, minimum: 0 },
        createdAt: { bsonType: 'date' },
      },
    },
  },
  users: {
    $jsonSchema: {
      bsonType: 'object',
      required: [
        'username',
        'passwordSalt',
        'passwordHash',
        'role',
        'createdAt',
        'updatedAt',
      ],
      additionalProperties: false,
      properties: {
        _id: { bsonType: 'objectId' },
        username: {
          bsonType: 'string',
          minLength: 3,
          maxLength: 64,
          pattern: '^[a-z0-9][a-z0-9_.-]*$',
        },
        passwordSalt: { bsonType: 'string', pattern: '^[a-fA-F0-9]{32}$' },
        passwordHash: { bsonType: 'string', pattern: '^[a-fA-F0-9]{128}$' },
        role: { bsonType: 'string', enum: ['viewer'] },
        createdAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' },
      },
    },
  },
};

async function ensureCollectionValidators(db) {
  const results = [];
  for (const [collection, validator] of Object.entries(collectionValidators)) {
    const collectionInfo = await db.listCollections({ name: collection }).next();
    if (!collectionInfo) {
      throw new Error(`MongoDB collection "${collection}" must be initialized before validation.`);
    }

    if (
      collectionInfo.options?.validationLevel === 'strict' &&
      collectionInfo.options?.validationAction === 'error' &&
      isDeepStrictEqual(collectionInfo.options?.validator, validator)
    ) {
      results.push({ collection, validationLevel: 'strict', validationAction: 'error' });
      continue;
    }

    await db.command({
      collMod: collection,
      validator,
      validationLevel: 'moderate',
      validationAction: 'warn',
    });

    const invalidDocuments = await db
      .collection(collection)
      .countDocuments({ $nor: [validator] });
    if (invalidDocuments > 0) {
      results.push({
        collection,
        validationLevel: 'moderate',
        validationAction: 'warn',
        invalidDocuments,
      });
      continue;
    }

    await db.command({
      collMod: collection,
      validator,
      validationLevel: 'strict',
      validationAction: 'error',
    });
    results.push({ collection, validationLevel: 'strict', validationAction: 'error' });
  }
  return results;
}

module.exports = { collectionValidators, ensureCollectionValidators };
