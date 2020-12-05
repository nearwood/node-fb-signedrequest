const crypto = require('crypto');

module.exports.parseSignedRequest = function parseSignedRequest(signedRequest, secret) {
  if (!signedRequest || typeof signedRequest !== 'string') {
    throw new Error("Invalid argument: signedRequest");
  }

  if (!secret || typeof secret !== 'string') {
    throw new Error("Invalid argument: secret");
  }

  try {
    const [signatureReceived, encodedPayload] = signedRequest.split('.', 2);
    const payload = b64decode(encodedPayload)
    const data = JSON.parse(payload);

    const hmac = crypto.createHmac('sha256', secret).update(payload);
    const expectedSignature = hmac.digest('base64');

    if (signatureReceived === expectedSignature) {
      return data;
    } else {
      throw new Error("Signature mismatch");
    }
  } catch (err) {
    throw new Error(`Could not parse signed request: ${err}`);
  }
};

function b64decode(data) {
  const buff = Buffer.from(data, 'base64');
  return buff.toString('ascii');
}
module.exports.b64decode = b64decode;

function b64encode(text) {
  const buff = Buffer.from(text, 'ascii'); //utf8
  return buff.toString('base64');
}
module.exports.b64encode = b64encode;
