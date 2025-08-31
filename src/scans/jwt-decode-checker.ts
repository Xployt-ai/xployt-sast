import { Node, CallExpression } from 'ts-morph';
import { BaseChecker } from './base-checker';
import { SecurityFinding, BaseCheckerOptions } from '../types';

export class JwtDecodeChecker extends BaseChecker {
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
    if (this.isJwtDecodeCall(callExpression)) {
      const functionScope = this.findContainingFunction(callExpression);
      if (functionScope && !this.hasJwtVerifyInScope(functionScope, callExpression)) {
        const sourceFile = callExpression.getSourceFile();
        const lineAndColumn = sourceFile.getLineAndColumnAtPos(callExpression.getStart());
        
        const finding: SecurityFinding = {
          filePath: sourceFile.getFilePath(),
          line: lineAndColumn.line,
          column: lineAndColumn.column,
          message: 'Found jwt.decode without corresponding jwt.verify in same function scope - tokens should be verified before use',
          code: callExpression.getText(),
          severity: 'high',
          ruleId: 'jwt-decode-without-verify',
        };

        this.addFinding(finding);
      }
    }
  }

  private isJwtDecodeCall(callExpression: CallExpression): boolean {
    const expression = callExpression.getExpression();
    
    if (Node.isPropertyAccessExpression(expression)) {
      const object = expression.getExpression();
      const property = expression.getName();
      
      return (Node.isIdentifier(object) && object.getText() === 'jwt' && property === 'decode') ||
             (Node.isIdentifier(object) && object.getText() === 'jsonwebtoken' && property === 'decode');
    }
    
    return false;
  }

  private findContainingFunction(node: Node): Node | undefined {
    let current = node.getParent();
    
    while (current) {
      if (Node.isFunctionDeclaration(current) || 
          Node.isMethodDeclaration(current) || 
          Node.isArrowFunction(current) || 
          Node.isFunctionExpression(current)) {
        return current;
      }
      current = current.getParent();
    }
    
    return undefined;
  }

  private hasJwtVerifyInScope(functionScope: Node, decodeCall: CallExpression): boolean {
    const tokenVariable = this.extractTokenVariable(decodeCall);
    
    let hasVerify = false;
    functionScope.forEachDescendant((node: Node) => {
      if (Node.isCallExpression(node) && this.isJwtVerifyCall(node)) {
        if (!tokenVariable || this.usesTokenVariable(node, tokenVariable)) {
          hasVerify = true;
        }
      }
    });
    
    return hasVerify;
  }

  private isJwtVerifyCall(callExpression: CallExpression): boolean {
    const expression = callExpression.getExpression();
    
    if (Node.isPropertyAccessExpression(expression)) {
      const object = expression.getExpression();
      const property = expression.getName();
      
      return (Node.isIdentifier(object) && object.getText() === 'jwt' && property === 'verify') ||
             (Node.isIdentifier(object) && object.getText() === 'jsonwebtoken' && property === 'verify');
    }
    
    return false;
  }

  private extractTokenVariable(callExpression: CallExpression): string | undefined {
    const args = callExpression.getArguments();
    if (args.length > 0) {
      const firstArg = args[0];
      if (Node.isIdentifier(firstArg)) {
        return firstArg.getText();
      }
    }
    return undefined;
  }

  private usesTokenVariable(verifyCall: CallExpression, tokenVariable: string): boolean {
    const args = verifyCall.getArguments();
    if (args.length > 0) {
      const firstArg = args[0];
      if (Node.isIdentifier(firstArg)) {
        return firstArg.getText() === tokenVariable;
      }
    }
    return false;
  }
}
