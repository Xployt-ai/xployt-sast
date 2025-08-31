import { CodeInjectionChecker } from '../../scans/code-injection-checker';
import { TestProjectHelper } from '../test-utils';

describe('CodeInjectionChecker', () => {
  let testProject: TestProjectHelper;

  beforeEach(() => {
    testProject = new TestProjectHelper();
  });

  afterEach(() => {
    testProject.cleanup();
  });

  describe('eval() injection detection', () => {
    it('should detect critical vulnerability when tainted data is passed to eval()', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/eval', (req, res) => {
  const userCode = req.query.code;
  eval(userCode);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].ruleId).toBe('code-injection-eval');
      expect(result.findings[0].message).toContain('Code Injection via eval()');
      expect(result.findings[0].message).toContain('req.query');
    });

    it('should detect eval() with req.body data', () => {
      const code = `
import express from 'express';

const app = express();

app.post('/eval', (req, res) => {
  const script = req.body.script;
  eval(script);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].message).toContain('req.body');
    });

    it('should detect eval() with req.params data', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/eval/:code', (req, res) => {
  const { code } = req.params;
  eval(code);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].message).toContain('req.params');
    });

    it('should detect eval() with propagated taint through variable assignment', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/eval', (req, res) => {
  const userInput = req.query.input;
  const codeToExecute = userInput;
  eval(codeToExecute);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
    });

    it('should detect eval() with string concatenation', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/eval', (req, res) => {
  const userInput = req.query.input;
  const script = 'console.log(' + userInput + ')';
  eval(script);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
    });

    it('should detect eval() with template literals', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/eval', (req, res) => {
  const userInput = req.query.input;
  const script = \`console.log('\${userInput}')\`;
  eval(script);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
    });
  });

  describe('Function constructor injection detection', () => {
    it('should detect critical vulnerability when tainted data is passed to Function constructor', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/function', (req, res) => {
  const userCode = req.query.code;
  const fn = new Function(userCode);
  fn();
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].ruleId).toBe('code-injection-function');
      expect(result.findings[0].message).toContain('Function constructor');
    });

    it('should detect Function constructor with parameters and body', () => {
      const code = `
import express from 'express';

const app = express();

app.post('/function', (req, res) => {
  const params = req.body.params;
  const body = req.body.body;
  const fn = new Function(params, body);
  fn();
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
    });
  });

  describe('setTimeout/setInterval injection detection', () => {
    it('should detect high vulnerability when tainted data is passed to setTimeout as string', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/timeout', (req, res) => {
  const userCode = req.query.code;
  setTimeout(userCode, 1000);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].ruleId).toBe('code-injection-settimeout');
      expect(result.findings[0].message).toContain('setTimeout()');
    });

    it('should detect setInterval vulnerability', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/interval', (req, res) => {
  const userCode = req.query.code;
  setInterval(userCode, 1000);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].ruleId).toBe('code-injection-setinterval');
      expect(result.findings[0].message).toContain('setInterval()');
    });
  });

  describe('DOM-based injection detection', () => {
    it('should detect innerHTML vulnerability', () => {
      const code = `
const userInput = window.location.hash.substring(1);
const element = document.getElementById('content');
element.innerHTML = userInput;
`;

      testProject.createTestFile('client.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].ruleId).toBe('code-injection-innerhtml');
      expect(result.findings[0].message).toContain('innerHTML');
      expect(result.findings[0].message).toContain('window.location');
    });

    it('should detect event handler injection via setAttribute', () => {
      const code = `
const userInput = document.cookie;
const element = document.createElement('button');
element.setAttribute('onclick', userInput);
`;

      testProject.createTestFile('client.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].ruleId).toBe('code-injection-event-handler');
      expect(result.findings[0].message).toContain('onclick event handler');
      expect(result.findings[0].message).toContain('document.cookie');
    });

    it('should detect various event handler injections', () => {
      const code = `
const userInput = window.location.search;
const element = document.createElement('div');
element.setAttribute('onload', userInput);
element.setAttribute('onerror', userInput);
element.setAttribute('onmouseover', userInput);
`;

      testProject.createTestFile('client.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings.length).toBeGreaterThanOrEqual(3);
      result.findings.forEach(finding => {
        expect(finding.severity).toBe('high');
        expect(finding.ruleId).toBe('code-injection-event-handler');
      });
    });
  });

  describe('client-side taint sources', () => {
    it('should detect taint from window.location properties', () => {
      const code = `
const hash = window.location.hash;
const search = window.location.search;
const pathname = window.location.pathname;
eval(hash);
eval(search);
eval(pathname);
`;

      testProject.createTestFile('client.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(3);
      result.findings.forEach(finding => {
        expect(finding.severity).toBe('critical');
        expect(finding.message).toContain('window.location');
      });
    });

    it('should detect taint from form input values', () => {
      const code = `
const input = document.getElementById('userInput') as HTMLInputElement;
const userValue = input.value;
eval(userValue);
`;

      testProject.createTestFile('client.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].message).toContain('input.value');
    });

    it('should detect taint from postMessage events', () => {
      const code = `
window.addEventListener('message', (event) => {
  const data = event.data;
  eval(data);
});
`;

      testProject.createTestFile('client.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].message).toContain('postMessage');
    });

    it('should detect taint from API responses', () => {
      const code = `
fetch('/api/data')
  .then(response => response.json())
  .then(data => {
    eval(data.script);
  });
`;

      testProject.createTestFile('client.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].message).toContain('api.response');
    });
  });

  describe('complex taint propagation scenarios', () => {
    it('should trace taint through multiple variable assignments', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/complex', (req, res) => {
  const userInput = req.query.input;
  const step1 = userInput;
  const step2 = step1;
  const finalCode = step2;
  eval(finalCode);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].message).toContain('variable_assignment');
    });

    it('should trace taint through function calls', () => {
      const code = `
import express from 'express';

const app = express();

function processInput(input: string) {
  return input.toUpperCase();
}

app.get('/function-call', (req, res) => {
  const userInput = req.query.input;
  const processed = processInput(userInput);
  eval(processed);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].message).toContain('function_call');
    });

    it('should handle object destructuring of tainted sources', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/destructure', (req, res) => {
  const { code, script } = req.query;
  eval(code);
  eval(script);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(2);
      result.findings.forEach(finding => {
        expect(finding.severity).toBe('critical');
        expect(finding.message).toContain('req.query');
      });
    });

    it('should handle array destructuring of tainted sources', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/array-destructure', (req, res) => {
  const [first, second] = req.body.scripts;
  eval(first);
  eval(second);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(2);
      result.findings.forEach(finding => {
        expect(finding.severity).toBe('critical');
        expect(finding.message).toContain('req.body');
      });
    });
  });

  describe('safe patterns that should not trigger', () => {
    it('should not flag eval() with static strings', () => {
      const code = `
eval('console.log("This is safe")');
`;

      testProject.createTestFile('safe.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });

    it('should not flag setTimeout with function references', () => {
      const code = `
import express from 'express';

const app = express();

function safeFunction() {
  console.log('This is safe');
}

app.get('/safe-timeout', (req, res) => {
  setTimeout(safeFunction, 1000);
});
`;

      testProject.createTestFile('safe.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });

    it('should not flag innerHTML with static content', () => {
      const code = `
const element = document.getElementById('content');
element.innerHTML = '<p>This is safe static content</p>';
`;

      testProject.createTestFile('safe.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });

    it('should not flag non-event attributes in setAttribute', () => {
      const code = `
const userInput = req.query.className;
const element = document.createElement('div');
element.setAttribute('class', userInput);
`;

      testProject.createTestFile('safe.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('data flow tracing', () => {
    it('should provide complete data flow trace in vulnerability reports', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/trace', (req, res) => {
  const userInput = req.query.input;
  const processed = userInput.toLowerCase();
  const finalCode = 'console.log("' + processed + '")';
  eval(finalCode);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      const finding = result.findings[0];
      expect(finding.message).toContain('Data flow trace');
      expect(finding.message).toContain('req.query');
      expect(finding.message).toContain('function_call');
      expect(finding.message).toContain('string_concatenation');
      expect(finding.message).toContain('code execution sink');
    });
  });

  describe('multiple vulnerabilities in single file', () => {
    it('should detect all vulnerabilities in a file with multiple issues', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/multiple', (req, res) => {
  const userCode = req.query.code;
  const userScript = req.body.script;
  const userTimeout = req.params.timeout;
  
  eval(userCode);
  new Function(userScript)();
  setTimeout(userTimeout, 1000);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(3);
      
      const evalFinding = result.findings.find(f => f.ruleId === 'code-injection-eval');
      const functionFinding = result.findings.find(f => f.ruleId === 'code-injection-function');
      const timeoutFinding = result.findings.find(f => f.ruleId === 'code-injection-settimeout');
      
      expect(evalFinding).toBeDefined();
      expect(functionFinding).toBeDefined();
      expect(timeoutFinding).toBeDefined();
      
      expect(evalFinding?.severity).toBe('critical');
      expect(functionFinding?.severity).toBe('critical');
      expect(timeoutFinding?.severity).toBe('high');
    });
  });

  describe('edge cases and error handling', () => {
    it('should handle files with syntax errors gracefully', () => {
      const code = `
import express from 'express';

const app = express();

app.get('/broken', (req, res) => {
  const userInput = req.query.input
  // Missing semicolon and closing brace
`;

      testProject.createTestFile('broken.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      
      expect(() => {
        const result = checker.check();
        expect(result.findings).toBeDefined();
      }).not.toThrow();
    });

    it('should handle empty files', () => {
      testProject.createTestFile('empty.ts', '');
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
      expect(result.totalFiles).toBe(1);
    });

    it('should handle files with only comments', () => {
      const code = `
// This is just a comment file
/* 
 * No actual code here
 */
`;

      testProject.createTestFile('comments.ts', code);
      const checker = new CodeInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });
  });
});
