const { connectQueue, enqueueJob, dequeueJob } = require('./queue/redis');
async function test() {
  console.log("Dequeue blocking...");
  dequeueJob(0); // blocks
  setTimeout(async () => {
     console.log("Now enqueuing...");
     try {
       await enqueueJob(999);
       console.log("Enqueue success!");
     } catch(e) {
       console.log("Enqueue error:", e);
     }
  }, 1000);
}
test();
