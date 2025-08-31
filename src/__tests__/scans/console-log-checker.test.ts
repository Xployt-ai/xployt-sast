import { ConsoleLogChecker } from '../../scans/console-log-checker';
import { TestProjectHelper } from '../test-utils';

describe('ConsoleLogChecker', () => {
  let testHelper: TestProjectHelper;
  let checker: ConsoleLogChecker;

  beforeEach(() => {
    testHelper = new TestProjectHelper();
  });

  afterEach(() => {
    testHelper.cleanup();
  });

  it('should detect console.log statements', () => {
    const code = `
function debugFunction() {
  const value = 42;
  console.log('Debug value:', value);
  return value;
}
`;

    testHelper.createTestFile('debug.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].message).toContain('console.log');
    expect(result.findings[0].severity).toBe('low');
    expect(result.findings[0].ruleId).toBe('no-console-log');
    expect(result.findings[0].code).toContain('console.log');
  });

  it('should detect multiple console.log statements', () => {
    const code = `
function multipleDebug() {
  console.log('First log');
  const data = { name: 'test' };
  console.log('Data:', data);
  
  if (true) {
    console.log('Nested log');
  }
}
`;

    testHelper.createTestFile('multiple.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(3);
    expect(result.findings.every(f => f.ruleId === 'no-console-log')).toBe(true);
  });

  it('should not flag other console methods', () => {
    const code = `
function otherConsoleMethods() {
  console.error('This is an error');
  console.warn('This is a warning');
  console.info('This is info');
  console.debug('This is debug');
  console.table(['a', 'b', 'c']);
}
`;

    testHelper.createTestFile('otherMethods.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
  });

  it('should not flag non-console log calls', () => {
    const code = `
const logger = {
  log: (message: string) => console.error(message)
};

function useCustomLogger() {
  logger.log('This is not console.log');
  
  const customLog = (msg: string) => msg;
  customLog('Also not console.log');
}
`;

    testHelper.createTestFile('customLogger.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
  });

  it('should detect console.log in different contexts', () => {
    const code = `
class MyClass {
  method() {
    console.log('Method log');
  }
}

const arrowFunction = () => {
  console.log('Arrow function log');
};

function regularFunction() {
  console.log('Regular function log');
}

// Global scope
console.log('Global log');
`;

    testHelper.createTestFile('contexts.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(4);
    expect(result.findings.every(f => f.ruleId === 'no-console-log')).toBe(true);
  });

  it('should handle console.log with various arguments', () => {
    const code = `
function variousArgs() {
  console.log();
  console.log('simple string');
  console.log('string with', 'multiple', 'args');
  console.log({ object: 'value' });
  console.log(['array', 'values']);
  console.log('template', \`string \${42}\`);
}
`;

    testHelper.createTestFile('args.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(6);
    expect(result.findings.every(f => f.code.includes('console.log'))).toBe(true);
  });

  it('should provide correct file path and line information', () => {
    const code = `function test() {
  console.log('test message');
}`;

    const filePath = testHelper.createTestFile('lineTest.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].filePath).toBe(filePath);
    expect(result.findings[0].line).toBe(2);
    expect(result.findings[0].column).toBeGreaterThan(0);
  });

  it('should work with TypeScript syntax', () => {
    const code = `
interface User {
  name: string;
  age: number;
}

function processUser(user: User): void {
  console.log('Processing user:', user.name);
}

const users: User[] = [{ name: 'John', age: 30 }];
users.forEach(user => console.log('User:', user));
`;

    testHelper.createTestFile('typescript.ts', code);
    checker = new ConsoleLogChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(2);
    expect(result.findings.every(f => f.ruleId === 'no-console-log')).toBe(true);
  });
});
