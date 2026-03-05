const fs = require('fs');
const path = require('path');
const { cloneRepository } = require('../repo/cloner');
const { runAnalyzer } = require('../analyzer-client/client');
const { transitionJobState } = require('../jobs/stateMachine');

const SANDBOX_ROOT = path.resolve(__dirname, '../../tmp_sandbox');

async function processJob(jobId, repoUrl) {
    const jobSandboxDir = path.join(SANDBOX_ROOT, `job_${jobId}_${Date.now()}`);

    try {
        // Ensure sandbox root exists
        if (!fs.existsSync(SANDBOX_ROOT)) {
            fs.mkdirSync(SANDBOX_ROOT, { recursive: true });
        }

        // 1. CLONING STATE
        await transitionJobState(jobId, 'CLONING');
        await cloneRepository(repoUrl, jobSandboxDir);

        // 2. ANALYZING STATE
        await transitionJobState(jobId, 'ANALYZING');
        const results = await runAnalyzer(jobSandboxDir);

        // 3. COMPLETED STATE
        await transitionJobState(jobId, 'COMPLETED', { results });

    } catch (err) {
        console.error(`Job ${jobId} failed:`, err);
        await transitionJobState(jobId, 'FAILED', { error_message: err.message });
    } finally {
        // 4. CLEANUP GUARANTEE
        // Ensure the downloaded untrusted code is purged to prevent disk exhaustion and lateral movement.
        console.log(`Cleaning up sandbox for Job ${jobId}: ${jobSandboxDir}`);
        if (fs.existsSync(jobSandboxDir)) {
            fs.rmSync(jobSandboxDir, { recursive: true, force: true });
        }
    }
}

module.exports = {
    processJob
};
