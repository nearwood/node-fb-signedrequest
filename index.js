const crypto = require('crypto');

// export default const verifyFbSignature = (secret, data) => {

// };

const appSecret = 'abc123';
const hmac1 = crypto.createHmac('sha256', appSecret);
const hmac2 = crypto.createHmac('sha256', appSecret);

// const verifier = crypto.createVerify('sha256');
// const signer = crypto.createSign('sha256');

const testData = JSON.stringify({
  "algorithm": "HMAC-SHA256",
  "expires": 1291840400,
  "issued_at": 1291836800,
  "user_id": "218471"
});

hmac1.update(testData);
const sig1 = hmac1.digest('base64');

const signedRequest = `${sig1}.${b64encode(testData)}`; //req.body.signed_request

console.log(signedRequest);


const [encodedSig, payload] = signedRequest.split('.', 2);
const sig = b64decode(encodedSig);
const data = JSON.parse(b64decode(payload));

console.log('sig,data:', encodedSig, data);

hmac2.update(JSON.stringify(data));
const newSig = hmac2.digest('base64');

console.log("Are equal:", encodedSig === newSig);

function b64decode(data) {
  const buff = Buffer.from(data, 'base64');
  return buff.toString('ascii');
}

function b64encode(text) {
  const buff = Buffer.from(text, 'ascii'); //utf8
  return buff.toString('base64');
}