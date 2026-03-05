# PQC Migration Analyzer Platform

A research-grade platform for quantum cryptography migration analysis. 
This platform performs interprocedural, flow-sensitive static analysis of Java repositories to identify vulnerable public-key cryptographic primitives, calculate structural exposure, track tainted variables, and compute a Quantum Risk Score (QRS).

## Architecture

The project strictly adheres to a separated 3-layer architecture:
1. **Frontend**: Minimal vanilla HTML/JS dashboard.
2. **Backend**: Node.js Express orchestrator, managing Postgres database state and Redis job queues.
3. **Analyzer**: Standalone Java statically compiled CLI that executes the AST analysis.

---

## Prerequisites

Ensure you have the following installed on your system:
- **Java**: JDK 17 or higher
- **Maven**: For building the analyzer CLI
- **Node.js**: v16 or higher
- **PostgreSQL**: Running database instance
- **Redis**: Running in-memory data store queue

---

## Step-by-Step Run Instructions

### 1. Build the Java Analyzer
The backend relies on invoking the compiled Java CLI. You must build this first.

```bash
cd pqc-platform/analyzer
mvn clean package
```
*This will create the fat jar at `analyzer/target/analyzer-cli-1.0-SNAPSHOT-jar-with-dependencies.jar`.*

### 2. Setup the Database
Ensure PostgreSQL is running, then initialize the database tables.

```bash
# Log into your Postgres instance and create a database (e.g., pqcdb)
createdb pqcdb

# Apply the schema
cd pqc-platform/backend
psql -d pqcdb -f db/schema.sql
```

### 3. Start the Backend Orchestrator
Install the Node.js dependencies and start the API server & job worker.
Ensure Redis is running locally on port `6379`.

```bash
cd pqc-platform/backend
npm install

# Set your database credentials as environment variables
export PGUSER="your_postgres_user"
export PGPASSWORD="your_postgres_password"
export PGDATABASE="pqcdb"
export PGHOST="localhost"
export PGPORT="5432"

# Start the server (runs both the API on port 3000 and the Redis background worker)
npm start
```

### 4. Serve the Frontend
The frontend requires no build steps (no React/Vue). Simply serve the static files in the `frontend/` folder.

Open a new terminal:
```bash
cd pqc-platform/frontend
npx serve .
# OR if you prefer python:
# python3 -m http.server 8000
```

### 5. Access the Platform
1. Open your browser and navigate to the frontend URL (e.g., `http://localhost:3000` or `http://localhost:8000` depending on your serve tool).
2. **Login**: For testing, you must manually insert a user into your Postgres database since the registration endpoint was omitted per "minimal frontend" constraints:
   ```sql
   INSERT INTO users (username, password_hash) VALUES ('admin', 'password123');
   ```
3. Use `admin` / `password123` to log in.
4. Input a valid public GitHub repository URL into the dashboard to queue an analysis job.

---

## Running the Evaluation
To run the automated pipeline vs. baseline comparison script:

```bash
cd pqc-platform/evaluation
# Ensure the analyzer jar was built in step 1
python3 evaluate.py
```
*Note: You must edit `evaluate.py` to point to actual sandbox repository directories to see meaningful CSV outputs.*
