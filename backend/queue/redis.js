const redis = require('redis');

// Create Redis Client for normal operations (like rPush)
const client = redis.createClient({
    url: process.env.REDIS_URL || 'redis://localhost:6379'
});

// Create a duplicate client specifically for blocking operations
const blockingClient = client.duplicate();

client.on('error', err => console.error('Redis Client Error', err));
blockingClient.on('error', err => console.error('Redis BlockingClient Error', err));

async function connectQueue() {
    if (!client.isOpen) {
        await client.connect();
    }
    if (!blockingClient.isOpen) {
        await blockingClient.connect();
    }
}

async function enqueueJob(jobId) {
    await connectQueue();
    // Push job ID to the right side of the queue
    await client.rPush('pqc:jobs:queue', String(jobId));
}

async function dequeueJob(timeoutSeconds = 0) {
    await connectQueue();
    // BLPOP blocks until a job is available if timeout > 0. Must use separate client.
    const result = await blockingClient.blPop('pqc:jobs:queue', timeoutSeconds);
    return result ? result.element : null;
}

module.exports = {
    connectQueue,
    enqueueJob,
    dequeueJob,
    client
};
