import { JwtDecodeChecker } from '../../scans/jwt-decode-checker';
import { TestProjectHelper } from '../test-utils';

describe('JwtDecodeChecker', () => {
  let testHelper: TestProjectHelper;
  let checker: JwtDecodeChecker;

  beforeEach(() => {
    testHelper = new TestProjectHelper();
  });

  afterEach(() => {
    testHelper.cleanup();
  });

  it('should detect jwt.decode without verify in same function', () => {
    const code = `
import jwt from 'jsonwebtoken';

function unsafeJwtHandler(token: string) {
  const decoded = jwt.decode(token);
  return decoded;
}
`;

    testHelper.createTestFile('unsafe.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].message).toContain('jwt.decode without corresponding jwt.verify');
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].ruleId).toBe('jwt-decode-without-verify');
  });

  it('should not flag jwt.decode when jwt.verify is present in same function', () => {
    const code = `
import jwt from 'jsonwebtoken';

function safeJwtHandler(token: string, secret: string) {
  try {
    jwt.verify(token, secret);
    const decoded = jwt.decode(token);
    return decoded;
  } catch (error) {
    throw new Error('Invalid token');
  }
}
`;

    testHelper.createTestFile('safe.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
  });

  it('should detect multiple jwt.decode calls without verify', () => {
    const code = `
import jwt from 'jsonwebtoken';

function multipleUnsafe(token1: string, token2: string) {
  const decoded1 = jwt.decode(token1);
  const decoded2 = jwt.decode(token2);
  return { decoded1, decoded2 };
}
`;

    testHelper.createTestFile('multipleUnsafe.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(2);
    expect(result.findings.every(f => f.ruleId === 'jwt-decode-without-verify')).toBe(true);
  });

  it('should work with jsonwebtoken namespace import', () => {
    const code = `
import * as jsonwebtoken from 'jsonwebtoken';

function namespaceUnsafe(token: string) {
  const decoded = jsonwebtoken.decode(token);
  return decoded;
}
`;

    testHelper.createTestFile('namespace.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('jwt-decode-without-verify');
  });

  it('should handle different function types', () => {
    const code = `
import jwt from 'jsonwebtoken';

// Regular function
function regularFunction(token: string) {
  return jwt.decode(token);
}

// Arrow function
const arrowFunction = (token: string) => {
  return jwt.decode(token);
};

// Method in class
class TokenHandler {
  processToken(token: string) {
    return jwt.decode(token);
  }
}

// Function expression
const functionExpression = function(token: string) {
  return jwt.decode(token);
};
`;

    testHelper.createTestFile('functionTypes.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(4);
    expect(result.findings.every(f => f.ruleId === 'jwt-decode-without-verify')).toBe(true);
  });

  it('should not flag jwt.decode with verify using same token variable', () => {
    const code = `
import jwt from 'jsonwebtoken';

function safeWithSameVariable(token: string, secret: string) {
  jwt.verify(token, secret);
  const payload = jwt.decode(token);
  return payload;
}
`;

    testHelper.createTestFile('sameVariable.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
  });

  it('should flag jwt.decode when verify uses different token variable', () => {
    const code = `
import jwt from 'jsonwebtoken';

function differentVariables(token1: string, token2: string, secret: string) {
  jwt.verify(token1, secret);
  const payload = jwt.decode(token2);
  return payload;
}
`;

    testHelper.createTestFile('differentVariables.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('jwt-decode-without-verify');
  });

  it('should not flag non-jwt decode calls', () => {
    const code = `
const customJwt = {
  decode: (token: string) => token
};

function customDecoder(token: string) {
  return customJwt.decode(token);
}

function base64Decode(data: string) {
  return Buffer.from(data, 'base64').toString();
}
`;

    testHelper.createTestFile('nonJwt.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
  });

  it('should handle nested function scopes correctly', () => {
    const code = `
import jwt from 'jsonwebtoken';

function outerFunction(token: string, secret: string) {
  jwt.verify(token, secret);
  
  function innerFunction(innerToken: string) {
    return jwt.decode(innerToken); // This should be flagged
  }
  
  return innerFunction;
}
`;

    testHelper.createTestFile('nested.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('jwt-decode-without-verify');
  });

  it('should provide correct file path and line information', () => {
    const code = `import jwt from 'jsonwebtoken';

function test(token: string) {
  return jwt.decode(token);
}`;

    const filePath = testHelper.createTestFile('lineTest.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].filePath).toBe(filePath);
    expect(result.findings[0].line).toBe(4);
    expect(result.findings[0].column).toBeGreaterThan(0);
  });

  it('should handle complex verification patterns', () => {
    const code = `
import jwt from 'jsonwebtoken';

function complexVerification(token: string, secret: string) {
  try {
    const verified = jwt.verify(token, secret);
    if (verified) {
      const decoded = jwt.decode(token);
      return decoded;
    }
  } catch (error) {
    throw new Error('Verification failed');
  }
}
`;

    testHelper.createTestFile('complex.ts', code);
    checker = new JwtDecodeChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
  });
});
