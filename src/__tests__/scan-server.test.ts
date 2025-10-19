import http from 'http';
import { spawn } from 'child_process';

describe('scanner server', () => {
  let proc: any;
  const port = 18001;

  beforeAll(done => {
    proc = spawn(process.execPath, ['-e', `require('ts-node/register'); require('../server').default || require('../server')`], {
      env: { ...process.env, PORT: String(port) },
    });
    setTimeout(done, 500);
  }, 10000);

  afterAll(() => {
    try { proc.kill(); } catch {}
  });

  it('returns single-response payload', done => {
    const req = http.request({ method: 'POST', port, path: '/scan', headers: { 'content-type': 'application/json' } }, res => {
      let data = '';
      res.on('data', c => (data += c));
      res.on('end', () => {
        const obj = JSON.parse(data);
        expect(obj.progress).toBe(100);
        expect(Array.isArray(obj.vulnerabilities)).toBe(true);
        done();
      });
    });
    req.write(JSON.stringify({ path: process.cwd() }));
    req.end();
  });

  it('streams progress via NDJSON', done => {
    const req = http.request({ method: 'POST', port, path: '/scan?mode=stream', headers: { 'content-type': 'application/json', accept: 'application/x-ndjson' } }, res => {
      let received = 0;
      res.on('data', chunk => {
        const lines = chunk.toString().trim().split('\n').filter(Boolean);
        received += lines.length;
        if (lines.some(l => { try { return JSON.parse(l).progress === 100; } catch { return false; } })) {
          done();
        }
      });
    });
    req.write(JSON.stringify({ path: process.cwd() }));
    req.end();
  });
});


