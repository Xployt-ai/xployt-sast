import { TypeScriptServer } from '../ts-server';
import { SecurityFinding, CheckerResult, BaseCheckerOptions } from '../types';

export abstract class BaseChecker {
  protected tsServer: TypeScriptServer;
  protected findings: SecurityFinding[] = [];
  protected options: BaseCheckerOptions;

  constructor(options: BaseCheckerOptions) {
    this.options = options;
    this.tsServer = new TypeScriptServer(options.codebasePath);
  }

  public check(): CheckerResult {
    this.findings = [];
    const sourceFiles = this.tsServer.getSourceFiles();
    const filesWithFindings = new Set<string>();

    for (const sourceFile of sourceFiles) {
      this.checkFile(sourceFile);
    }

    this.findings.forEach(finding => filesWithFindings.add(finding.filePath));

    return {
      findings: this.findings,
      totalFiles: sourceFiles.length,
      filesWithFindings: filesWithFindings.size,
    };
  }

  protected abstract checkFile(sourceFile: any): void;

  protected addFinding(finding: SecurityFinding): void {
    this.findings.push(finding);
  }
}
