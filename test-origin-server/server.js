// This is the "real website" that we are protecting.
// In production, this would be your actual app server.
// Our proxy will sit IN FRONT of this server.

const express = require('express');
const app = express();

const PORT = Number(process.env.PORT || 4000);
app.disable('x-powered-by');

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/', (req, res) => {
  res.send(`
    <h1>Welcome to the Protected Website 🛡️</h1>
    <p>If you can see this, the request passed all security checks!</p>
    <p>Time: ${new Date().toLocaleTimeString()}</p>
  `);
});

app.get('/api/data', (req, res) => {
  res.json({ message: 'This is protected API data', timestamp: Date.now() });
});

app.listen(PORT, () => {
  console.log(`✅ Origin (real) server running at http://localhost:${PORT}`);
});
