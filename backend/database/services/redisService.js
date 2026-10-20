// This file handles all communication with Redis.
// Redis = super fast in-memory database, perfect for rate limiting & temporary IP blocks.

const { createClient } = require('redis');

const redisClient = createClient({
  url: process.env.REDIS_URL || 'redis://localhost:6379'
});

redisClient.on('error', (err) => console.error('❌ Redis Error:', err));

async function connectRedis() {
  if (!redisClient.isOpen) {
    await redisClient.connect();
    console.log('✅ Connected to Redis');
  }
}

// Increment request count for an IP, used for rate limiting
async function incrementRequestCount(ip, windowSeconds) {
  const key = `rate:${ip}`;
  const count = await redisClient.eval(
    "local count = redis.call('INCR', KEYS[1]); if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]); end; return count",
    { keys: [key], arguments: [String(windowSeconds)] },
  );
  return Number(count);
}

// Block an IP for a certain duration (in seconds)
async function blockIP(ip, durationSeconds, reason = 'rate_limit_exceeded') {
  const key = `blocked:${ip}`;
  await redisClient.set(key, reason, { EX: durationSeconds });
}

// Check if an IP is currently blocked
async function isBlocked(ip) {
  const key = `blocked:${ip}`;
  const result = await redisClient.get(key);
  return result;
}

async function listBlockedIPs() {
  const blocked = [];
  for await (const key of redisClient.scanIterator({ MATCH: 'blocked:*', COUNT: 100 })) {
    const ip = key.slice('blocked:'.length);
    const [reason, ttlSeconds] = await Promise.all([
      redisClient.get(key),
      redisClient.ttl(key),
    ]);
    if (ttlSeconds > 0) {
      blocked.push({ ip, reason: reason || 'manual', ttlSeconds });
    }
  }
  return blocked.sort((left, right) => left.ip.localeCompare(right.ip));
}

async function unblockIP(ip) {
  return redisClient.del(`blocked:${ip}`);
}

async function isRedisReady() {
  return redisClient.isReady;
}

module.exports = {
  redisClient,
  connectRedis,
  incrementRequestCount,
  blockIP,
  isBlocked,
  listBlockedIPs,
  unblockIP,
  isRedisReady,
};
