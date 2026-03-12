-- PostgreSQL Schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Job states
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'job_state') THEN
        CREATE TYPE job_state AS ENUM ('PENDING', 'CLONING', 'ANALYZING', 'COMPLETED', 'FAILED');
    END IF;
END $$;

-- Jobs table
CREATE TABLE IF NOT EXISTS jobs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    repo_url TEXT NOT NULL,
    state job_state DEFAULT 'PENDING',
    results JSONB, -- Stores the AnalyzerResponse
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Analysis Jobs table (Required by system audit)
CREATE TABLE IF NOT EXISTS analysis_jobs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    repo_url TEXT NOT NULL,
    state job_state DEFAULT 'PENDING',
    results JSONB,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Findings table (Required by system audit)
CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    job_id INTEGER REFERENCES analysis_jobs(id),
    file_path TEXT NOT NULL,
    line_number INTEGER,
    algorithm VARCHAR(100),
    key_size INTEGER,
    exposure VARCHAR(50),
    tainted BOOLEAN,
    risk_score NUMERIC(5,2)
);
