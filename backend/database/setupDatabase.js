require('dotenv').config();

const mongoose = require('mongoose');
const SecurityEvent = require('./models/SecurityEvent');
const User = require('./models/User');
const { ensureCollectionValidators } = require('./validators');

async function main() {
  const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/anti_cloudflare';

  try {
    await mongoose.connect(mongoUri, { serverSelectionTimeoutMS: 5000 });
    await Promise.all([SecurityEvent.init(), User.init()]);
    const validationResults = await ensureCollectionValidators(mongoose.connection.db);
    console.info(
      `MongoDB database "${mongoose.connection.name}" is ready with collections "${SecurityEvent.collection.collectionName}" and "${User.collection.collectionName}", indexes, and schema validation: ${validationResults.map(({ collection, validationLevel, validationAction, invalidDocuments }) => `${collection}=${validationLevel}/${validationAction}${invalidDocuments ? ` (${invalidDocuments} existing invalid documents)` : ''}`).join(', ')}.`,
    );
  } finally {
    await mongoose.disconnect();
  }
}

main().catch((error) => {
  console.error('Failed to initialize the MongoDB database:', error);
  process.exitCode = 1;
});
