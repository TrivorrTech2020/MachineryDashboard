const jwt = require('jsonwebtoken');

module.exports = function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  const { session } = req.body || {};
  if (!session) return res.status(401).json({ error: 'No session' });

  const { SESSION_SECRET } = process.env;
  if (!SESSION_SECRET) return res.status(503).json({ error: 'Not configured' });

  try {
    const payload = jwt.verify(session, SESSION_SECRET);
    res.status(200).json({ ok: true, name: payload.userName });
  } catch {
    res.status(401).json({ error: 'Invalid or expired session' });
  }
};
