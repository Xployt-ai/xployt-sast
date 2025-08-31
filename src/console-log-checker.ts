import { Node, CallExpression } from 'ts-morph';
import { BaseChecker } from './base-checker';
import { SecurityFinding, BaseCheckerOptions } from './types';

export class ConsoleLogChecker extends BaseChecker {
  constructor(options: BaseCheckerOptions) {
    super(options);
  }

  protected checkFile(sourceFile: any): void {
    sourceFile.forEachDescendant((node: Node) => {
      if (Node.isCallExpression(node)) {
        this.checkCallExpression(node);
      }
    });
  }

  private checkCallExpression(callExpression: CallExpression): void {
    const expression = callExpression.getExpression();
    
    if (Node.isPropertyAccessExpression(expression)) {
      const object = expression.getExpression();
      const property = expression.getName();
      
      if (Node.isIdentifier(object) && object.getText() === 'console' && property === 'log') {
        const sourceFile = callExpression.getSourceFile();
        const lineAndColumn = sourceFile.getLineAndColumnAtPos(callExpression.getStart());
        
        const finding: SecurityFinding = {
          filePath: sourceFile.getFilePath(),
          line: lineAndColumn.line,
          column: lineAndColumn.column,
          message: 'Found console.log statement - should be removed in production',
          code: callExpression.getText(),
          severity: 'low',
          ruleId: 'no-console-log',
        };

        this.addFinding(finding);
      }
    }
  }
}
