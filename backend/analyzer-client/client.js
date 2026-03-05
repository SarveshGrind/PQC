const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const path = require('path');

// CLI absolute location. In production, this would be an env var pointing to a built jar.
const ANALYZER_JAR = path.resolve(__dirname, '../../analyzer/target/analyzer-cli-1.0-SNAPSHOT-jar-with-dependencies.jar');
const ANALYZER_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes max analysis time

/**
 * Invokes the completely isolated Java CLI Analyzer.
 * The backend knows NOTHING about AST parsing or Java. It strictly executes the CLI
 * and parses the standard AnalyzerResponse JSON contract from stdout.
 */
async function runAnalyzer(repoPath) {
    const cmd = `java -jar "${ANALYZER_JAR}" --repoPath "${repoPath}"`;

    try {
        const { stdout } = await execPromise(cmd, {
            timeout: ANALYZER_TIMEOUT_MS,
            maxBuffer: 10 * 1024 * 1024 // 10MB JSON response buffer
        });

        // Parse the strictly typed contract JSON
        const response = JSON.parse(stdout);
        return response;
    } catch (err) {
        throw new Error(`Analyzer execution failed: ${err.message}`);
    }
}

module.exports = {
    runAnalyzer
};
