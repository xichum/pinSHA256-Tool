const http = require('http');
const tls = require('tls');
const url = require('url');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const PORT = process.env.PORT || 3000;

function derToPem(derBuffer) {
    const base64 = derBuffer.toString('base64');
    const lines = base64.match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

function fetchTCP(host, port) {
    return new Promise((resolve, reject) => {
        const options = { host, port, rejectUnauthorized: false, servername: host, timeout: 5000 };
        const socket = tls.connect(options, () => {
            const cert = socket.getPeerX509Certificate();
            if (cert) {
                resolve({ pem: cert.toString(), proto: 'TCP' });
            } else {
                const legacyCert = socket.getPeerCertificate(true);
                if (legacyCert && legacyCert.raw) {
                    resolve({ pem: derToPem(legacyCert.raw), proto: 'TCP (Legacy)' });
                } else {
                    reject(new Error("No certificate returned by server"));
                }
            }
            socket.destroy();
        });
        socket.on('error', err => reject(err));
        socket.on('timeout', () => { socket.destroy(); reject(new Error("TCP Connection Timeout (5s)")); });
    });
}

function fetchQUIC(host, port) {
    return new Promise((resolve, reject) => {
        const args = ['s_client', '-showcerts', '-quic', '-alpn', 'h3', '-connect', `${host}:${port}`];
        const child = execFile('openssl', args, { timeout: 5000 }, (error, stdout) => {
            const match = stdout ? stdout.match(/-----BEGIN CERTIFICATE-----\n[\s\S]*?\n-----END CERTIFICATE-----/) : null;
            if (match) resolve({ pem: match[0] + '\n', proto: 'UDP/QUIC' });
            else reject(new Error("QUIC Handshake Failed or Unsupported"));
        });
        child.stdin.end();
        setTimeout(() => { try { child.kill('SIGKILL'); } catch(e) {} }, 6000);
    });
}

const server = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    const parsedUrl = url.parse(req.url, true);
    
    if (parsedUrl.pathname === '/health') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end('OK');
        return;
    }

    if (parsedUrl.pathname === '/' || parsedUrl.pathname === '/index.html') {
        const filePath = path.join(__dirname, 'index.html');
        fs.readFile(filePath, (err, content) => {
            if (err) {
                res.writeHead(500);
                res.end("Error loading index.html");
            } else {
                res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
                res.end(content);
            }
        });
        return;
    }

    if (parsedUrl.pathname === '/fetch') {
        const target = parsedUrl.query.target;
        if (!target) return res.writeHead(400, {'Content-Type': 'application/json'}).end(JSON.stringify({ error: "Missing target parameter" }));

        let host = target;
        let port = 443;
        const lastColonIdx = target.lastIndexOf(':');
        
        if (lastColonIdx > target.indexOf(']')) {
            host = target.substring(0, lastColonIdx).replace(/[\[\]]/g, '');
            port = parseInt(target.substring(lastColonIdx + 1), 10);
        } else if (target.split(':').length === 2) {
            host = target.split(':')[0];
            port = parseInt(target.split(':')[1], 10);
        }

        host = host.replace(/\/$/, '').trim();
        console.log(`[Fetch Request] Target: ${host}:${port}`);

        try {
            const result = await fetchTCP(host, port).catch(tcpErr => {
                console.log(`[TCP Failed] ${host}:${port} - ${tcpErr.message}. Trying QUIC...`);
                return fetchQUIC(host, port).catch(quicErr => {
                    throw new Error(`TCP Error: ${tcpErr.message} | QUIC Error: ${quicErr.message}`);
                });
            });
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify(result));
        } catch (err) {
            console.error(`[All Failed] ${host}:${port} -> ${err.message}`);
            res.writeHead(502, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ error: err.message }));
        }
        return;
    }

    res.writeHead(404).end("Not Found");
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`Universal Cert Tool running on port ${PORT}`);
});
