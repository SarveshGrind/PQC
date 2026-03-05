-- PostgreSQL Schema

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
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
