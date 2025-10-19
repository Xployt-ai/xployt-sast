import express from 'express';
import * as path from 'path';
import * as fs from 'fs';
import cors from 'cors';
import {
  checkDangerousInnerHTML,
  checkJwtDecodeWithoutVerify,
  checkNoSQLInjection,
  checkCodeInjection,
} from './index';
import { CheckerResult, SecurityFinding } from './types';

type ScannerMode = 'single' | 'stream';

function mapSeverity(sev?: SecurityFinding['severity']): string {
  return sev ? String(sev) : 'unknown';
}

function mapVulnerability(ruleId?: string): string {
  if (!ruleId) return 'unknown';
  if (ruleId.startsWith('code-injection')) return 'code_injection';
  if (ruleId.startsWith('nosql-')) return 'nosql_injection';
  if (ruleId === 'dangerous-inner-html') return 'xss';
  if (ruleId === 'jwt-decode-without-verify') return 'jwt_without_verify';
  return ruleId.replace(/-/g, '_');
}

function toVulnerabilities(findings: SecurityFinding[], basePath: string) {
  return findings.map(f => ({
    file_path: path.isAbsolute(f.filePath) ? path.relative(basePath, f.filePath) : f.filePath,
    line: Number(f.line || 0),
    description: f.message,
    vulnerability: mapVulnerability(f.ruleId),
    severity: mapSeverity(f.severity),
    confidence_level: f.severity === 'critical' || f.severity === 'high' ? 'high' : 'medium',
  }));
}

function runAllChecks(codebasePath: string): CheckerResult {
  const results: CheckerResult[] = [];
  results.push(checkDangerousInnerHTML(codebasePath));
  results.push(checkNoSQLInjection(codebasePath));
  results.push(checkJwtDecodeWithoutVerify(codebasePath));
  results.push(checkCodeInjection(codebasePath));

  const findings = results.flatMap(r => r.findings);
  const totalFiles = Math.max(...results.map(r => r.totalFiles), 0);
  const filesWithFindings = results.reduce((acc, r) => Math.max(acc, r.filesWithFindings), 0);
  return { findings, totalFiles, filesWithFindings };
}

function resolveMode(req: any): ScannerMode {
  const q = (req.query?.mode as string) || (req.query?.stream as string);
  if (q && (q === '1' || q === 'true' || q === 'stream')) return 'stream';
  const hdr = (req.headers['x-mode'] as string) || (req.headers['x-stream'] as string);
  if (hdr && (hdr === '1' || hdr === 'true' || hdr === 'stream')) return 'stream';
  const accept = (req.headers['accept'] as string) || '';
  if (accept.includes('text/event-stream') || accept.includes('application/x-ndjson')) return 'stream';
  return 'single';
}

const app = express();
app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.get('/health', (_req: any, res: any) => {
  res.json({ status: 'ok' });
});

app.post('/scan', async (req: any, res: any) => {
  try {
    const codebasePath = path.resolve(String(req.body?.path || ''));
    if (!codebasePath || !fs.existsSync(codebasePath)) {
      return res.status(400).json({ error: 'Invalid path; directory does not exist' });
    }

    const mode = resolveMode(req);

    if (mode === 'stream') {
      const wantsSse =
        ((req.query?.sse as string) || '').toString() === '1' ||
        String(req.headers['accept'] || '').includes('text/event-stream');

      if (wantsSse) {
        res.setHeader('Content-Type', 'text/event-stream');
      } else {
        res.setHeader('Content-Type', 'application/x-ndjson');
      }
      res.setHeader('Cache-Control', 'no-cache');
      res.setHeader('Connection', 'keep-alive');

      const write = (obj: any) => {
        if (wantsSse) {
          res.write(`data: ${JSON.stringify(obj)}\n\n`);
        } else {
          res.write(JSON.stringify(obj) + '\n');
        }
      };

      write({ progress: 5, message: 'Preparing...' });
      await new Promise(r => setTimeout(r, 100));
      write({ progress: 15, message: 'Indexing files' });

      await new Promise(r => setTimeout(r, 100));
      const dangerous = checkDangerousInnerHTML(codebasePath);
      if (dangerous.findings.length) {
        write({ progress: 35, message: 'Analyzing (dangerous-html)', vulnerabilities: toVulnerabilities(dangerous.findings, codebasePath) });
      } else {
        write({ progress: 35, message: 'Analyzing (dangerous-html)' });
      }

      await new Promise(r => setTimeout(r, 50));
      const nosql = checkNoSQLInjection(codebasePath);
      if (nosql.findings.length) {
        write({ progress: 55, message: 'Analyzing (nosql)', vulnerabilities: toVulnerabilities(nosql.findings, codebasePath) });
      } else {
        write({ progress: 55, message: 'Analyzing (nosql)' });
      }

      await new Promise(r => setTimeout(r, 50));
      const jwt = checkJwtDecodeWithoutVerify(codebasePath);
      if (jwt.findings.length) {
        write({ progress: 70, message: 'Analyzing (jwt)', vulnerabilities: toVulnerabilities(jwt.findings, codebasePath) });
      } else {
        write({ progress: 70, message: 'Analyzing (jwt)' });
      }

      await new Promise(r => setTimeout(r, 50));
      const codeinj = checkCodeInjection(codebasePath);
      if (codeinj.findings.length) {
        write({ progress: 85, message: 'Analyzing (code-injection)', vulnerabilities: toVulnerabilities(codeinj.findings, codebasePath) });
      } else {
        write({ progress: 85, message: 'Analyzing (code-injection)' });
      }

      await new Promise(r => setTimeout(r, 50));
      write({ progress: 100, message: 'Scan completed' });
      return res.end();
    }

    const { findings } = runAllChecks(codebasePath);
    const payload = {
      progress: 100,
      status: 'complete',
      vulnerabilities: toVulnerabilities(findings, codebasePath),
    };
    return res.json(payload);
  } catch (e: any) {
    return res.status(500).json({ error: e?.message || 'Scan failed' });
  }
});

const PORT = Number(process.env.PORT || 8001);
app.listen(PORT, () => {
  // eslint-disable-next-line no-console
  console.log(`Scanner service listening on http://localhost:${PORT}`);
});


