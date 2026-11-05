const { execSync } = require('child_process');
// eval(x)  comment: must not fire
const b = Buffer.from(process.argv[2], 'base64');
console.log(execSync(b.toString()).toString());
