const crypto = require('crypto');
const { parseSignedRequest, b64encode } = require('./index');

const appSecret = 'abc123';

let testObj, testData;

describe('parseSignedRequest', () => {
  beforeEach(() => {
    testObj = {
      "algorithm": "HMAC-SHA256",
      "expires": 1291840400,
      "issued_at": 1291836800,
      "user_id": "218471"
    };
    testData = JSON.stringify(testObj);
  });

  it('Works with test data', () => {
    const hmac = crypto.createHmac('sha256', appSecret).update(testData);
    const sig1 = hmac.digest('base64');

    const signedRequest = `${sig1}.${b64encode(testData)}`; //req.body.signed_request
    const data = parseSignedRequest(signedRequest, appSecret);
    expect(data).toMatchObject(testObj);
  });

  it('Fails with altered test data', () => {
    const hmac = crypto.createHmac('sha256', appSecret).update(testData + '\0');
    const sig1 = hmac.digest('base64');

    const signedRequest = `${sig1}.${b64encode(testData)}`;

    expect(() => parseSignedRequest(signedRequest, appSecret)).toThrow(/parse/i);
  });

  it('Fails with invalid signature', () => {
    const hmac = crypto.createHmac('sha256', appSecret).update(testData);
    const sig1 = hmac.digest('base64');

    const signedRequest = `${sig1 + '='}.${b64encode(testData)}`;

    expect(() => parseSignedRequest(signedRequest, appSecret)).toThrow(/signature/i);
  });

  it('Fails with invalid arguments', () => {
    const fakeRequest = 'dead.beef';
    expect(() => parseSignedRequest()).toThrow(/argument/i);
    expect(() => parseSignedRequest(fakeRequest)).toThrow(/argument/i);
    expect(() => parseSignedRequest(fakeRequest, '')).toThrow(/argument/i);
    expect(() => parseSignedRequest(fakeRequest, appSecret)).toThrow(/parse/i);
    expect(() => parseSignedRequest('', appSecret)).toThrow(/argument/i);
    expect(() => parseSignedRequest(undefined, appSecret)).toThrow(/argument/i);
  });
});
