const crypto = require('crypto');

function verifyWebhook(req, secret) {
  const payload = JSON.stringify(req.body);
  const expected = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  const supplied = req.headers['x-signature'] || '';
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(supplied));
}

function eventId(req) {
  return String(req.headers['x-event-id'] || '').trim();
}

module.exports = { verifyWebhook, eventId };
