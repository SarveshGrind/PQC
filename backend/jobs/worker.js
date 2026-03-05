const { dequeueJob } = require('../queue/redis');
const db = require('../db/pool');
const { processJob } = require('../sandbox/manager');

async function runWorker() {
    console.log("Job worker started. Polling Redis...");

    while (true) {
        try {
            // Block until a job is added to the queue
            const jobId = await dequeueJob(0);
            if (jobId) {
                console.log(`[Worker] Picked up Job ID: ${jobId}`);

                // Fetch job details to get repoUrl
                const result = await db.query('SELECT repo_url FROM jobs WHERE id = $1', [jobId]);
                const job = result.rows[0];

                if (job) {
                    await processJob(jobId, job.repo_url);
                } else {
                    console.error(`Job ${jobId} not found in database.`);
                }
            }
        } catch (err) {
            console.error("Worker error:", err);
            // Brief pause to prevent hot-looping on Redis connection errors
            await new Promise(resolve => setTimeout(resolve, 5000));
        }
    }
}

module.exports = {
    runWorker
};
