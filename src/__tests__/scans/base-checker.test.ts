import { BaseChecker } from '../../scans/base-checker';
import { SecurityFinding, BaseCheckerOptions } from '../../types';
import { TestProjectHelper } from '../test-utils';

class TestChecker extends BaseChecker {
  private shouldFindIssues: boolean;

  constructor(options: BaseCheckerOptions, shouldFindIssues = false) {
    super(options);
    this.shouldFindIssues = shouldFindIssues;
  }

  protected checkFile(sourceFile: any): void {
    if (this.shouldFindIssues) {
      const finding: SecurityFinding = {
        filePath: sourceFile.getFilePath(),
        line: 1,
        column: 1,
        message: 'Test finding',
        code: 'test code',
        severity: 'medium' as const,
        ruleId: 'test-rule',
      };
      this.addFinding(finding);
    }
  }
}

describe('BaseChecker', () => {
  let testHelper: TestProjectHelper;

  beforeEach(() => {
    testHelper = new TestProjectHelper();
    testHelper.createTsConfig();
  });

  afterEach(() => {
    testHelper.cleanup();
  });

  it('should initialize with correct options', () => {
    const options = { codebasePath: testHelper.getTempDir() };
    const checker = new TestChecker(options);

    expect(checker).toBeInstanceOf(BaseChecker);
  });

  it('should return empty results when no issues found', () => {
    testHelper.createTestFile('empty.ts', 'const x = 1;');
    
    const checker = new TestChecker({ codebasePath: testHelper.getTempDir() });
    const result = checker.check();

    expect(result.findings).toHaveLength(0);
    expect(result.totalFiles).toBe(1);
    expect(result.filesWithFindings).toBe(0);
  });

  it('should return findings when issues are detected', () => {
    testHelper.createTestFile('withIssue.ts', 'const x = 1;');
    
    const checker = new TestChecker({ codebasePath: testHelper.getTempDir() }, true);
    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.totalFiles).toBe(1);
    expect(result.filesWithFindings).toBe(1);
    expect(result.findings[0].message).toBe('Test finding');
    expect(result.findings[0].ruleId).toBe('test-rule');
  });

  it('should handle multiple files', () => {
    testHelper.createTestFile('file1.ts', 'const a = 1;');
    testHelper.createTestFile('file2.ts', 'const b = 2;');
    testHelper.createTestFile('file3.ts', 'const c = 3;');
    
    const checker = new TestChecker({ codebasePath: testHelper.getTempDir() }, true);
    const result = checker.check();

    expect(result.findings).toHaveLength(3);
    expect(result.totalFiles).toBe(3);
    expect(result.filesWithFindings).toBe(3);
  });

  it('should correctly count files with findings', () => {
    testHelper.createTestFile('file1.ts', 'const a = 1;');
    testHelper.createTestFile('file2.ts', 'const b = 2;');
    
    class SelectiveChecker extends BaseChecker {
      protected checkFile(sourceFile: any): void {
        const filePath = sourceFile.getFilePath();
        if (filePath.includes('file1')) {
          this.addFinding({
            filePath: sourceFile.getFilePath(),
            line: 1,
            column: 1,
            message: 'Issue in file1',
            code: 'test',
            severity: 'low' as const,
            ruleId: 'test',
          });
        }
      }
    }
    
    const checker = new SelectiveChecker({ codebasePath: testHelper.getTempDir() });
    const result = checker.check();

    expect(result.findings).toHaveLength(1);
    expect(result.totalFiles).toBe(2);
    expect(result.filesWithFindings).toBe(1);
  });

  it('should reset findings between checks', () => {
    testHelper.createTestFile('test.ts', 'const x = 1;');
    
    const checker = new TestChecker({ codebasePath: testHelper.getTempDir() }, true);
    
    const result1 = checker.check();
    const result2 = checker.check();

    expect(result1.findings).toHaveLength(1);
    expect(result2.findings).toHaveLength(1);
  });

  it('should handle files in subdirectories', () => {
    testHelper.createTestFile('src/components/Component.tsx', 'export const Component = () => null;');
    testHelper.createTestFile('src/utils/helper.ts', 'export const helper = () => {};');
    
    const checker = new TestChecker({ codebasePath: testHelper.getTempDir() }, true);
    const result = checker.check();

    expect(result.totalFiles).toBe(2);
    expect(result.findings).toHaveLength(2);
  });

  it('should handle TypeScript and JavaScript files', () => {
    testHelper.createTestFile('typescript.ts', 'interface Test { name: string; }');
    testHelper.createTestFile('javascript.js', 'const obj = { name: "test" };');
    testHelper.createTestFile('react.tsx', 'export const Component = () => <div />;');
    
    const checker = new TestChecker({ codebasePath: testHelper.getTempDir() });
    const result = checker.check();

    expect(result.totalFiles).toBeGreaterThanOrEqual(3);
  });

  it('should provide access to TypeScript server', () => {
    class TsServerAccessChecker extends BaseChecker {
      public getTsServer() {
        return this.tsServer;
      }

      protected checkFile(): void {
        // No implementation needed for this test
      }
    }

    const checker = new TsServerAccessChecker({ codebasePath: testHelper.getTempDir() });
    const tsServer = checker.getTsServer();

    expect(tsServer).toBeDefined();
    expect(typeof tsServer.getSourceFiles).toBe('function');
  });
});
