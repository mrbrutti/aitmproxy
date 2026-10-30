// A real HTTP/2 upstream for the proxy e2e tests that ALSO speaks HTTP/1.1
// (allowHTTP1), the way a production HTTPS origin does — so the test can prove
// the proxy mirrors ALPN both ways (h2 client -> h2, 1.1 client -> 1.1) with no
// downgrade surprise. It echoes the request and reports the negotiated ALPN.
// Args: <cert> <key> <port>.
import http2 from 'node:http2';
import fs from 'node:fs';

const [cert, key, port] = process.argv.slice(2);
const server = http2.createSecureServer({
  cert: fs.readFileSync(cert),
  key: fs.readFileSync(key),
  allowHTTP1: true,
});

// HTTP/2 requests arrive as streams.
server.on('stream', (stream, headers) => {
  const chunks = [];
  stream.on('data', (c) => chunks.push(c));
  stream.on('end', () => {
    const payload = JSON.stringify({
      method: headers[':method'],
      path: headers[':path'],
      headers,
      body: Buffer.concat(chunks).toString('utf8'),
      alpn: stream.session.alpnProtocol,
    });
    stream.respond({ ':status': 200, 'content-type': 'application/json' });
    stream.end(payload);
  });
});

// HTTP/1.1 requests (allowHTTP1 fallback) arrive as normal req/res.
server.on('request', (req, res) => {
  if (req.httpVersion === '2.0') return; // already handled by 'stream'
  const chunks = [];
  req.on('data', (c) => chunks.push(c));
  req.on('end', () => {
    const payload = JSON.stringify({
      method: req.method,
      path: req.url,
      headers: req.headers,
      body: Buffer.concat(chunks).toString('utf8'),
      alpn: req.socket.alpnProtocol || 'http/1.1',
    });
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(payload);
  });
});

server.on('error', (e) => { console.log('error ' + e.message); process.exit(1); });
server.listen(parseInt(port, 10), '127.0.0.1', () => console.log('listening'));
