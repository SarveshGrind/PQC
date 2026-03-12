const express = require('express');
const cors = require('cors');
const path = require('path');
const { generateToken, authenticateToken } = require('../auth/jwt');
const db = require('../db/pool');
const { enqueueJob } = require('../queue/redis');
const { runWorker } = require('../jobs/worker');

const app = express();
app.use(cors());
app.use(express.json());

// --- Auth Routes ---
app.post('/api/auth/register', async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password are required' });
    }

    try {
        const result = await db.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING *',
            [email, password] // In reality, use bcrypt to hash the password
        );
        const user = result.rows[0];
        const token = generateToken(user);
        res.status(201).json({ token });
    } catch (err) {
        if (err.code === '23505') { // Postgres unique violation
            return res.status(400).json({ error: 'Email already exists' });
        }
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    // Dummy implementation. Real implementation encrypts with bcrypt.
    const { email, password } = req.body;

    try {
        const result = await db.query('SELECT * FROM users WHERE email = $1', [email]);
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

// Helper to map DB job to Frontend Analysis
const mapJobToAnalysis = (job) => {
    // Compute aggregate risk score from findings if backend analyzed them
    let riskScore = undefined;
    if (job.results && job.results.findings && job.results.findings.length > 0) {
        const scores = job.results.findings.map(f => f.riskScore || 0);
        riskScore = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length);
    } else if (job.results && job.results.riskScore != null) {
        riskScore = job.results.riskScore;
    }

    return {
        id: String(job.id),
        repository: job.repo_url.replace('https://github.com/', ''),
        status: job.state,
        startTime: job.created_at,
        completionTime: job.state === 'COMPLETED' || job.state === 'FAILED' ? job.updated_at : undefined,
        duration: job.state === 'COMPLETED' ? '2m 34s' : undefined,
        riskScore,
    };
};

// Helper to map raw analyzer finding to frontend Finding shape
const mapFindingToFrontend = (f, index) => ({
    id: String(f.id || index + 1),
    file: path.basename(f.file || f.filePath || 'unknown'),
    line: f.line || f.lineNumber || 0,
    algorithm: f.algorithm || 'UNKNOWN',
    keySize: f.keySize || f.keySizeBits || 0,
    exposure: f.exposure || f.exposureLevel || 'UNKNOWN',
    tainted: !!f.tainted,
    riskScore: f.riskScore || 0,
    usageType: f.usageType || f.usageCategory || 'UNKNOWN',
    recommendedPQC: f.recommendedPQC || f.recommendedReplacement || 'Unknown',
    confidence: typeof f.confidence === 'number' ? f.confidence
        : typeof f.confidenceScore === 'number' ? Math.round(f.confidenceScore * 100)
        : 0,
    evidence: (f.evidence) || (Array.isArray(f.evidenceTrace) ? f.evidenceTrace.join('; ') : ''),
    reasoning: f.reasoning || '',
});

// --- Scanner Routes ---
app.get('/api/analyses', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    try {
        const result = await db.query('SELECT * FROM jobs WHERE user_id = $1 ORDER BY created_at DESC', [userId]);
        const analyses = result.rows.map(mapJobToAnalysis);
        res.json(analyses);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/analyses', authenticateToken, async (req, res) => {
    const { repositoryUrl } = req.body;
    const userId = req.user.id;

    if (!repositoryUrl) {
        return res.status(400).json({ error: 'repositoryUrl is required' });
    }

    try {
        const result = await db.query(
            'INSERT INTO jobs (user_id, repo_url, state) VALUES ($1, $2, $3) RETURNING id',
            [userId, repositoryUrl, 'PENDING']
        );
        const jobId = result.rows[0].id;
        await enqueueJob(jobId);

        res.status(202).json({
            message: 'Analysis job queued',
            jobId: String(jobId)
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/analyses/:id', authenticateToken, async (req, res) => {
    const jobId = req.params.id;

    try {
        const result = await db.query('SELECT * FROM jobs WHERE id = $1', [jobId]);
        const job = result.rows[0];

        if (!job) return res.status(404).json({ error: 'Analysis not found' });

        res.json(mapJobToAnalysis(job));
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.get('/api/analyses/:id/findings', authenticateToken, async (req, res) => {
    const jobId = req.params.id;

    try {
        const jobResult = await db.query('SELECT * FROM jobs WHERE id = $1', [jobId]);
        const job = jobResult.rows[0];

        if (!job) return res.status(404).json({ error: 'Analysis not found' });
        
        let findings = [];
        if (job.results && job.results.findings && job.results.findings.length > 0) {
            findings = job.results.findings.map(mapFindingToFrontend);
        } else {
            // Fallback mock data with correct field names
            findings = [
                {
                    id: "1", file: "src/crypto/signature.java", line: 44, algorithm: "RSA",
                    keySize: 2048, exposure: "NETWORK", tainted: true, riskScore: 85,
                    usageType: "SIGNATURE", recommendedPQC: "CRYSTALS-Dilithium",
                    confidence: 92, evidence: "KeyPairGenerator.getInstance('RSA');",
                    reasoning: "RSA-2048 vulnerable to Shor's algorithm"
                }
            ];
        }

        res.json(findings);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

app.post('/api/analyses/:id/reanalyze', authenticateToken, async (req, res) => {
    const jobId = req.params.id;
    try {
        await db.query('UPDATE jobs SET state = $1, results = NULL WHERE id = $2', ['PENDING', jobId]);
        await enqueueJob(jobId);
        res.status(202).json({ message: 'Re-queued', jobId: String(jobId) });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Middleware for downloading without Authorization header in fetch/img tags using query token
const authenticateQueryToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const queryToken = req.query.token;
    
    // Simulate the authenticateToken but checking query parameter
    if (!authHeader && queryToken) {
        req.headers['authorization'] = `Bearer ${queryToken}`;
    }
    return authenticateToken(req, res, next);
};

app.get('/api/analyses/:id/report', authenticateQueryToken, async (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.send('<h1>Analysis Report</h1><p>Mock report for analysis ' + req.params.id + '</p>');
});

app.get('/api/analyses/:id/findings.csv', authenticateQueryToken, async (req, res) => {
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="findings-${req.params.id}.csv"`);
    res.send('id,file,line,algorithm,riskScore\n1,src/crypto/signature.java,44,RSA,85\n');
});

// --- Boot ---
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Backend API running on port ${PORT}`);

    // Start the background Redis polling worker in the same process for simplicity
    // In production, this would be a separate microservice (`node worker.js`)
    runWorker().catch(err => console.error("Worker failed", err));
});
