const jwt = require('jsonwebtoken');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });

  const { SSO_SECRET, SESSION_SECRET, PORTAL_URL = 'https://portal.sgfinfra.com' } = process.env;
  if (!SSO_SECRET || !SESSION_SECRET) {
    return res.status(503).json({ error: 'SSO not configured' });
  }

  let payload;
  try {
    payload = jwt.verify(token, SSO_SECRET);
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  if (payload.appId !== 'machinery') {
    return res.status(403).json({ error: 'Invalid app' });
  }

  const { jti, userId, userName } = payload;
  if (!jti) return res.status(401).json({ error: 'Invalid token format' });

  // Consume the one-time JTI via the portal
  let consumeRes;
  try {
    consumeRes = await fetch(`${PORTAL_URL}/api/sso/consume`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jti }),
    });
  } catch {
    return res.status(503).json({ error: 'Could not reach portal' });
  }

  if (!consumeRes.ok) {
    return res.status(401).json({ error: 'Token already used or expired' });
  }

  const sessionToken = jwt.sign({ userId, userName }, SESSION_SECRET, { expiresIn: '7d' });
  res.status(200).json({ ok: true, name: userName, session: sessionToken });
};
