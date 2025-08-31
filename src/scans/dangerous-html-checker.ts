import { Node, JsxAttribute } from 'ts-morph';
import { BaseChecker } from './base-checker';
import { SecurityFinding, BaseCheckerOptions } from '../types';

export class DangerousInnerHTMLChecker extends BaseChecker {
  constructor(options: BaseCheckerOptions) {
    super(options);
  }

  protected checkFile(sourceFile: any): void {
    sourceFile.forEachDescendant((node: Node) => {
      if (Node.isJsxAttribute(node)) {
        this.checkJsxAttribute(node);
      }
    });
  }

  private checkJsxAttribute(attribute: JsxAttribute): void {
    const nameNode = attribute.getNameNode();
    const name = nameNode.getText();
    
    if (name === 'dangerouslySetInnerHTML') {
      const sourceFile = attribute.getSourceFile();
      const lineAndColumn = sourceFile.getLineAndColumnAtPos(attribute.getStart());
      
      const finding: SecurityFinding = {
        filePath: sourceFile.getFilePath(),
        line: lineAndColumn.line,
        column: lineAndColumn.column,
        message: 'Found dangerouslySetInnerHTML attribute - potential XSS vulnerability',
        code: attribute.getText(),
        severity: 'high',
        ruleId: 'dangerous-inner-html',
      };

      this.addFinding(finding);
    }
  }
}
