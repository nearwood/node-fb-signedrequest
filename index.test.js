const crypto = require('crypto');
const { verifyFbSignature, b64encode, b64decode } = require('./index');

const appSecret = 'abc123';
const testObj = {
  "algorithm": "HMAC-SHA256",
  "expires": 1291840400,
  "issued_at": 1291836800,
  "user_id": "218471"
};
const testData = JSON.stringify(testObj);

describe('sig check', () => {
  it('checks sig', () => {
    const hmac1 = crypto.createHmac('sha256', appSecret);

    hmac1.update(testData);
    const sig1 = hmac1.digest('base64');

    const signedRequest = `${sig1}.${b64encode(testData)}`; //req.body.signed_request
    const data = verifyFbSignature(signedRequest, appSecret);
    expect(data).toMatchObject(testObj);
  });
});
