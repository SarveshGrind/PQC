const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const util = require('util');
const execPromise = util.promisify(exec);

const MAX_SIZE_BYTES = 500 * 1024 * 1024; // 500 MB hard limit
const CLONE_TIMEOUT_MS = 300000; // 5 minutes

async function getDirectorySize(dirPath) {
    let size = 0;
    const files = await fs.promises.readdir(dirPath, { withFileTypes: true });

    for (const file of files) {
        const itemPath = path.join(dirPath, file.name);
        if (file.isDirectory()) {
            size += await getDirectorySize(itemPath);
        } else if (file.isFile()) {
            const stats = await fs.promises.stat(itemPath);
            size += stats.size;
        }
    }
    return size;
}

async function cloneRepository(repoUrl, destination) {
    console.log(`Cloning ${repoUrl} into ${destination}...`);

    // 1. Timeout enforced via exec options
    // 2. --depth 1 isolates history size
    await execPromise(`git clone --depth 1 "${repoUrl}" "${destination}"`, {
        timeout: CLONE_TIMEOUT_MS,
        killSignal: 'SIGKILL'
    });

    // 3. Size limit enforced post-clone
    const size = await getDirectorySize(destination);
    if (size > MAX_SIZE_BYTES) {
        throw new Error(`Repository exceeds maximum allowed size of ${MAX_SIZE_BYTES} bytes. Found ${size} bytes.`);
    }

    return destination;
}

module.exports = {
    cloneRepository
};
