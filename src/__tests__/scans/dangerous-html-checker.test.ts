import { DangerousInnerHTMLChecker } from '../../scans/dangerous-html-checker';
import { TestProjectHelper } from '../test-utils';

describe('DangerousInnerHTMLChecker', () => {
  let testHelper: TestProjectHelper;
  let checker: DangerousInnerHTMLChecker;

  beforeEach(() => {
    testHelper = new TestProjectHelper();
  });

  afterEach(() => {
    testHelper.cleanup();
  });

  it('should detect dangerouslySetInnerHTML usage', () => {
    const reactCode = `
import React from 'react';

function MyComponent() {
  const htmlContent = '<p>Hello World</p>';
  return <div dangerouslySetInnerHTML={{ __html: htmlContent }} />;
}
`;

    testHelper.createTestFile('Component.tsx', reactCode);
    checker = new DangerousInnerHTMLChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].message).toContain('dangerouslySetInnerHTML');
    expect(result.findings[0].severity).toBe('high');
    expect(result.findings[0].ruleId).toBe('dangerous-inner-html');
    expect(result.findings[0].code).toContain('dangerouslySetInnerHTML');
  });

  it('should detect multiple dangerouslySetInnerHTML usages', () => {
    const reactCode = `
import React from 'react';

function MyComponent() {
  const htmlContent1 = '<p>Hello</p>';
  const htmlContent2 = '<p>World</p>';
  
  return (
    <div>
      <div dangerouslySetInnerHTML={{ __html: htmlContent1 }} />
      <span dangerouslySetInnerHTML={{ __html: htmlContent2 }} />
    </div>
  );
}
`;

    testHelper.createTestFile('MultipleComponent.tsx', reactCode);
    checker = new DangerousInnerHTMLChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(2);
    expect(result.findings.every(f => f.ruleId === 'dangerous-inner-html')).toBe(true);
  });

  it('should not flag regular JSX attributes', () => {
    const reactCode = `
import React from 'react';

function MyComponent() {
  return (
    <div className="container" id="main">
      <p>Safe content</p>
      <input type="text" placeholder="Enter text" />
    </div>
  );
}
`;

    testHelper.createTestFile('SafeComponent.tsx', reactCode);
    checker = new DangerousInnerHTMLChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
  });

  it('should work with nested components', () => {
    const reactCode = `
import React from 'react';

function ParentComponent() {
  return (
    <div>
      <ChildComponent />
    </div>
  );
}

function ChildComponent() {
  const dangerousHtml = '<script>alert("xss")</script>';
  return <div dangerouslySetInnerHTML={{ __html: dangerousHtml }} />;
}
`;

    testHelper.createTestFile('NestedComponent.tsx', reactCode);
    checker = new DangerousInnerHTMLChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].ruleId).toBe('dangerous-inner-html');
  });

  it('should handle files without JSX', () => {
    const regularCode = `
export function utilityFunction() {
  return 'Hello World';
}

const config = {
  apiUrl: 'https://api.example.com',
  timeout: 5000
};
`;

    testHelper.createTestFile('utils.ts', regularCode);
    checker = new DangerousInnerHTMLChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(0);
    expect(result.totalFiles).toBe(1);
  });

  it('should provide correct file path and line information', () => {
    const reactCode = `import React from 'react';

function Component() {
  return <div dangerouslySetInnerHTML={{ __html: 'test' }} />;
}`;

    const filePath = testHelper.createTestFile('LineTest.tsx', reactCode);
    checker = new DangerousInnerHTMLChecker({ codebasePath: testHelper.getTempDir() });

    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.findings[0].filePath).toBe(filePath);
    expect(result.findings[0].line).toBe(4);
    expect(result.findings[0].column).toBeGreaterThan(0);
  });
});
