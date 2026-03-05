const db = require('../db/pool');

/**
 * Valid transitions:
 * PENDING -> CLONING
 * CLONING -> ANALYZING
 * ANALYZING -> COMPLETED
 * ANY -> FAILED
 */
async function transitionJobState(jobId, newState, updatePayload = {}) {
    const validStates = ['PENDING', 'CLONING', 'ANALYZING', 'COMPLETED', 'FAILED'];
    if (!validStates.includes(newState)) {
        throw new Error(`Invalid state transition: ${newState}`);
    }

    let query = `UPDATE jobs SET state = $1, updated_at = CURRENT_TIMESTAMP`;
    let params = [newState];
    let paramIdx = 2;

    if (updatePayload.results) {
        query += `, results = $${paramIdx++}`;
        params.push(updatePayload.results);
    }

    if (updatePayload.error_message) {
        query += `, error_message = $${paramIdx++}`;
        params.push(updatePayload.error_message);
    }

    query += ` WHERE id = $${paramIdx}`;
    params.push(jobId);

    await db.query(query, params);
    console.log(`[Job ${jobId}] State transitioned to ${newState}`);
}

async function getJobState(jobId) {
    const result = await db.query('SELECT state FROM jobs WHERE id = $1', [jobId]);
    return result.rows[0]?.state;
}

module.exports = {
    transitionJobState,
    getJobState
};
