import { NoSQLInjectionChecker } from '../../scans/nosql-injection-checker';
import { TestProjectHelper } from '../test-utils';

describe('NoSQLInjectionChecker', () => {
  let testProject: TestProjectHelper;

  beforeEach(() => {
    testProject = new TestProjectHelper();
  });

  afterEach(() => {
    testProject.cleanup();
  });

  describe('$where injection detection', () => {
    it('should detect critical vulnerability when tainted data is used in $where clause', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/users', (req, res) => {
  const { condition } = req.query;
  User.find({ $where: condition });
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].ruleId).toBe('nosql-where-injection');
      expect(result.findings[0].message).toContain('$where JavaScript Injection');
      expect(result.findings[0].message).toContain('req.query');
    });

    it('should detect $where injection with where() method', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/users', (req, res) => {
  const condition = req.body.where;
  User.where(condition);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].ruleId).toBe('nosql-where-injection');
      expect(result.findings[0].message).toContain('req.body');
    });
  });

  describe('operator injection detection', () => {
    it('should detect operator injection with computed property names', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.post('/login', (req, res) => {
  const { field } = req.body;
  User.findOne({ [field]: 'admin' });
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].ruleId).toBe('nosql-operator-injection');
      expect(result.findings[0].message).toContain('Query Operator Injection');
      expect(result.findings[0].message).toContain('req.body');
    });
  });

  describe('direct query injection detection', () => {
    it('should detect when entire query is constructed from tainted data', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/search', (req, res) => {
  const query = req.query.filter;
  User.find(query);
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('high');
      expect(result.findings[0].ruleId).toBe('nosql-direct-injection');
      expect(result.findings[0].message).toContain('Direct Query Injection');
    });
  });

  describe('taint propagation', () => {
    it('should track taint through variable assignments', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/users', (req, res) => {
  const userInput = req.params.id;
  const queryParam = userInput;
  User.find({ $where: queryParam });
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].message).toContain('req.params');
      expect(result.findings[0].message).toContain('variable_assignment');
    });

    it('should track taint through function calls', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

function processInput(input) {
  return input;
}

app.get('/users', (req, res) => {
  const userInput = req.query.search;
  const processed = processInput(userInput);
  User.find({ $where: processed });
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].message).toContain('function_call');
    });

    it('should track taint through object destructuring', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.post('/users', (req, res) => {
  const { username, condition } = req.body;
  User.find({ $where: condition });
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].severity).toBe('critical');
      expect(result.findings[0].message).toContain('req.body');
    });
  });

  describe('multiple taint sources', () => {
    it('should detect vulnerabilities from different request properties', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/users', (req, res) => {
  const paramId = req.params.id;
  const querySearch = req.query.search;
  const bodyFilter = req.body.filter;
  const headerToken = req.headers.authorization;

  User.find({ $where: paramId });
  User.findOne({ [querySearch]: 'value' });
  User.updateOne(bodyFilter);
  User.deleteOne({ token: headerToken });
});
`;

      testProject.createTestFile('vulnerable.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(3); // headerToken in deleteOne is safe
      
      const whereInjection = result.findings.find(f => f.ruleId === 'nosql-where-injection');
      const operatorInjection = result.findings.find(f => f.ruleId === 'nosql-operator-injection');
      const directInjection = result.findings.find(f => f.ruleId === 'nosql-direct-injection');

      expect(whereInjection).toBeDefined();
      expect(operatorInjection).toBeDefined();
      expect(directInjection).toBeDefined();

      expect(whereInjection?.message).toContain('req.params');
      expect(operatorInjection?.message).toContain('req.query');
      expect(directInjection?.message).toContain('req.body');
    });
  });

  describe('safe usage patterns', () => {
    it('should not flag safe value usage in queries', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/users', (req, res) => {
  const username = req.body.username;
  User.find({ username: username }); // Safe - value usage
  User.findById(req.params.id); // Safe - specific method
});
`;

      testProject.createTestFile('safe.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });

    it('should not flag non-Express routes', () => {
      const code = `
import User from './models/User';

function regularFunction() {
  const condition = getUserInput();
  User.find({ $where: condition }); // Not from Express route
}
`;

      testProject.createTestFile('safe.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });

    it('should not flag hardcoded queries', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/users', (req, res) => {
  User.find({ status: 'active' }); // Safe - hardcoded
  User.where('age > 18'); // Safe - hardcoded
});
`;

      testProject.createTestFile('safe.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(0);
    });
  });

  describe('router usage', () => {
    it('should detect vulnerabilities in router handlers', () => {
      const code = `
import express from 'express';
import User from './models/User';

const router = express.Router();

router.post('/search', (req, res) => {
  const { operator } = req.body;
  User.find({ [operator]: 'admin' });
});

export default router;
`;

      testProject.createTestFile('router.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].ruleId).toBe('nosql-operator-injection');
    });
  });

  describe('complex propagation scenarios', () => {
    it('should handle multiple assignment chains', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/complex', (req, res) => {
  const input = req.query.data;
  const step1 = input;
  const step2 = step1;
  const final = step2;
  
  User.find({ $where: final });
});
`;

      testProject.createTestFile('complex.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      expect(result.findings[0].message).toContain('req.query');
      expect(result.findings[0].message).toContain('variable_assignment');
    });
  });

  describe('mongoose method coverage', () => {
    it('should detect vulnerabilities across all mongoose methods', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.post('/test', (req, res) => {
  const malicious = req.body.payload;
  
  User.find({ $where: malicious });
  User.findOne({ $where: malicious });
  User.findById({ $where: malicious });
  User.findOneAndUpdate({ $where: malicious });
  User.findOneAndDelete({ $where: malicious });
  User.updateOne({ $where: malicious });
  User.updateMany({ $where: malicious });
  User.deleteOne({ $where: malicious });
  User.deleteMany({ $where: malicious });
  User.aggregate([{ $match: { $where: malicious } }]);
});
`;

      testProject.createTestFile('methods.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings.length).toBeGreaterThan(5);
      result.findings.forEach(finding => {
        expect(finding.ruleId).toBe('nosql-where-injection');
        expect(finding.severity).toBe('critical');
      });
    });
  });

  describe('data flow trace reporting', () => {
    it('should include complete data flow trace in findings', () => {
      const code = `
import express from 'express';
import User from './models/User';

const app = express();

app.get('/trace', (req, res) => {
  const original = req.params.id;
  const intermediate = original;
  
  User.find({ $where: intermediate });
});
`;

      testProject.createTestFile('trace.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();

      expect(result.findings).toHaveLength(1);
      const finding = result.findings[0];
      
      expect(finding.message).toContain('Data flow trace:');
      expect(finding.message).toContain('Taint originated from req.params');
      expect(finding.message).toContain('variable_assignment');
      expect(finding.message).toContain('reached database query sink');
    });
  });

  describe('edge cases', () => {
    it('should handle empty files', () => {
      testProject.createTestFile('empty.ts', '');
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();
      expect(result.findings).toHaveLength(0);
    });

    it('should handle files without Express routes', () => {
      const code = `
const regularFunction = () => {
  console.log('No Express here');
};
`;
      testProject.createTestFile('no-express.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();
      expect(result.findings).toHaveLength(0);
    });

    it('should handle malformed route handlers', () => {
      const code = `
import express from 'express';
const app = express();

app.get('/malformed'); // No handler function
app.post('/incomplete', function() {}); // No parameters
`;
      testProject.createTestFile('malformed.ts', code);
      const checker = new NoSQLInjectionChecker({ codebasePath: testProject.getTempDir() });
      const result = checker.check();
      expect(result.findings).toHaveLength(0);
    });
  });
});
