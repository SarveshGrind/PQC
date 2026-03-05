const express = require('express');
const cors = require('cors');
const { generateToken, authenticateToken } = require('../auth/jwt');
const db = require('../db/pool');
const { enqueueJob } = require('../queue/redis');
const { runWorker } = require('../jobs/worker');

const app = express();
app.use(cors());
app.use(express.json());

// --- Auth Routes ---
app.post('/api/login', async (req, res) => {
    // Dummy implementation. Real implementation encrypts with bcrypt.
    const { username, password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        const user = result.rows[0];

        if (!user || user.password_hash !== password) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = generateToken(user);
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Scanner Routes ---
app.post('/api/analyze', authenticateToken, async (req, res) => {
    const { repoUrl } = req.body;
    const userId = req.user.id;

    if (!repoUrl) {
        return res.status(400).json({ error: 'repoUrl is required' });
    }

    try {
        // Create job in PENDING state
        const result = await db.query(
            'INSERT INTO jobs (user_id, repo_url, state) VALUES ($1, $2, $3) RETURNING id',
            [userId, repoUrl, 'PENDING']
        );
        const jobId = result.rows[0].id;

        // Push to Redis Queue asynchronously
        await enqueueJob(jobId);

        res.status(202).json({
            message: 'Analysis job queued',
            jobId,
            statusEndpoint: `/api/jobs/${jobId}`
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/jobs/:id', authenticateToken, async (req, res) => {
    const jobId = req.params.id;

    try {
        const result = await db.query('SELECT id, repo_url, state, results, error_message, updated_at FROM jobs WHERE id = $1', [jobId]);
        const job = result.rows[0];

        if (!job) {
            return res.status(404).json({ error: 'Job not found' });
        }

        res.json(job);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// --- Boot ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend API running on port ${PORT}`);

    // Start the background Redis polling worker in the same process for simplicity
    // In production, this would be a separate microservice (`node worker.js`)
    runWorker().catch(err => console.error("Worker failed", err));
});
