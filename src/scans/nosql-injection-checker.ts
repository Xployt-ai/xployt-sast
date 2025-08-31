import { 
  Node, 
  CallExpression, 
  VariableDeclaration, 
  PropertyAccessExpression,
  Identifier,
  ObjectBindingPattern,
  ArrayBindingPattern,
  BindingElement,
  ObjectLiteralExpression,
  PropertyAssignment,
  ComputedPropertyName,
  StringLiteral,
  SourceFile,
  SyntaxKind
} from 'ts-morph';
import { BaseChecker } from './base-checker';
import { SecurityFinding, BaseCheckerOptions } from '../types';

interface TaintedVariable {
  name: string;
  nodeId: string;
  sourceType: 'req.params' | 'req.query' | 'req.body' | 'req.headers';
  filePath: string;
  line: number;
  column: number;
}

interface DataFlowTrace {
  origin: TaintedVariable;
  propagationPath: Array<{
    filePath: string;
    line: number;
    column: number;
    operation: string;
  }>;
}

export class NoSQLInjectionChecker extends BaseChecker {
  private taintedVariables = new Map<string, TaintedVariable>();
  private dataFlowTraces = new Map<string, DataFlowTrace>();
  
  constructor(options: BaseCheckerOptions) {
    super(options);
  }

  protected checkFile(sourceFile: SourceFile): void {
    if (this.verbose) console.log(`[NoSQL] start file: ${sourceFile.getFilePath()}`);
    this.identifyTaintSources(sourceFile);
    this.propagateTaint(sourceFile);
    this.identifyVulnerableSinks(sourceFile);
    if (this.verbose)
      console.log(
        `[NoSQL] end file: ${sourceFile.getFilePath()} (tainted=${this.taintedVariables.size}, findings=${this.findings.length})`
      );
  }

  private identifyTaintSources(sourceFile: SourceFile): void {
    sourceFile.forEachDescendant((node: Node) => {
      if (Node.isCallExpression(node)) {
        this.checkExpressRoute(node, sourceFile);
      }
    });
  }

  private checkExpressRoute(callExpr: CallExpression, sourceFile: SourceFile): void {
    const expression = callExpr.getExpression();
    
    if (!Node.isPropertyAccessExpression(expression)) return;

    const propertyName = expression.getName();
    const httpMethods = ['get', 'post', 'put', 'delete', 'patch', 'head', 'options'];
    
    if (!httpMethods.includes(propertyName.toLowerCase())) return;

    const objectExpr = expression.getExpression();
    const objectText = objectExpr.getText();
    
    if (!objectText.includes('app') && !objectText.includes('router')) return;

    const args = callExpr.getArguments();
    if (args.length < 2) return;

    const handlerArg = args[args.length - 1];
    
    if (Node.isArrowFunction(handlerArg) || Node.isFunctionExpression(handlerArg)) {
      const parameters = handlerArg.getParameters();
      if (parameters.length >= 1) {
        const reqParam = parameters[0];
        const reqParamName = reqParam.getName();
        if (this.verbose) console.log(`[NoSQL] route handler found: req param "${reqParamName}" in ${sourceFile.getFilePath()}`);
        this.findTaintSourcesInFunction(handlerArg, reqParamName, sourceFile);
      }
    }
  }

  private findTaintSourcesInFunction(funcNode: Node, reqParamName: string, sourceFile: SourceFile): void {
    funcNode.forEachDescendant((node: Node) => {
      if (Node.isVariableDeclaration(node)) {
        this.checkVariableDeclaration(node, reqParamName, sourceFile);
      }
    });
  }

  private checkVariableDeclaration(varDecl: VariableDeclaration, reqParamName: string, sourceFile: SourceFile): void {
    const initializer = varDecl.getInitializer();
    if (!initializer) return;

    const nameNode = varDecl.getNameNode();
    const taintInfo = this.analyzeTaintSource(initializer, reqParamName);
    
    if (taintInfo) {
      const lineAndColumn = sourceFile.getLineAndColumnAtPos(varDecl.getStart());
      
      if (Node.isIdentifier(nameNode)) {
        this.registerTaintedVariable(nameNode.getText(), taintInfo, sourceFile.getFilePath(), lineAndColumn);
      } else if (Node.isObjectBindingPattern(nameNode)) {
        this.handleObjectDestructuring(nameNode, taintInfo, sourceFile.getFilePath(), lineAndColumn);
      } else if (Node.isArrayBindingPattern(nameNode)) {
        this.handleArrayDestructuring(nameNode, taintInfo, sourceFile.getFilePath(), lineAndColumn);
      }
    }
  }

  private analyzeTaintSource(node: Node, reqParamName: string): TaintedVariable['sourceType'] | null {
    const nodeText = node.getText();
    
    if (nodeText.includes(`${reqParamName}.params`)) return 'req.params';
    if (nodeText.includes(`${reqParamName}.query`)) return 'req.query';
    if (nodeText.includes(`${reqParamName}.body`)) return 'req.body';
    if (nodeText.includes(`${reqParamName}.headers`)) return 'req.headers';
    
    return null;
  }

  private registerTaintedVariable(
    name: string, 
    sourceType: TaintedVariable['sourceType'], 
    filePath: string, 
    lineAndColumn: { line: number; column: number }
  ): void {
    const nodeId = `${filePath}:${lineAndColumn.line}:${lineAndColumn.column}:${name}`;
    const taintedVar: TaintedVariable = {
      name,
      nodeId,
      sourceType,
      filePath,
      line: lineAndColumn.line,
      column: lineAndColumn.column
    };
    
    this.taintedVariables.set(nodeId, taintedVar);
    this.dataFlowTraces.set(nodeId, {
      origin: taintedVar,
      propagationPath: []
    });
  }

  private handleObjectDestructuring(
    bindingPattern: ObjectBindingPattern, 
    sourceType: TaintedVariable['sourceType'], 
    filePath: string, 
    lineAndColumn: { line: number; column: number }
  ): void {
    bindingPattern.getElements().forEach(element => {
      if (Node.isBindingElement(element)) {
        const name = element.getName();
        if (name) {
          this.registerTaintedVariable(name, sourceType, filePath, lineAndColumn);
        }
      }
    });
  }

  private handleArrayDestructuring(
    bindingPattern: ArrayBindingPattern, 
    sourceType: TaintedVariable['sourceType'], 
    filePath: string, 
    lineAndColumn: { line: number; column: number }
  ): void {
    bindingPattern.getElements().forEach((element, index) => {
      if (Node.isBindingElement(element)) {
        const name = element.getName();
        if (name) {
          this.registerTaintedVariable(`${name}[${index}]`, sourceType, filePath, lineAndColumn);
        }
      }
    });
  }

  private propagateTaint(sourceFile: SourceFile): void {
    sourceFile.forEachDescendant((node: Node) => {
      if (Node.isVariableDeclaration(node)) {
        this.checkTaintPropagation(node, sourceFile);
      } else if (Node.isBinaryExpression(node) && node.getOperatorToken().getKind() === SyntaxKind.EqualsToken) {
        this.checkAssignmentTaintPropagation(node, sourceFile);
      }
    });
  }

  private checkTaintPropagation(varDecl: VariableDeclaration, sourceFile: SourceFile): void {
    const initializer = varDecl.getInitializer();
    if (!initializer) return;

    const nameNode = varDecl.getNameNode();
    if (!Node.isIdentifier(nameNode)) return;

    const newVarName = nameNode.getText();
    const lineAndColumn = sourceFile.getLineAndColumnAtPos(varDecl.getStart());

    if (Node.isIdentifier(initializer)) {
      const sourceVarName = initializer.getText();
      const taintedVar = this.findTaintedVariableByName(sourceVarName);
      
      if (taintedVar) {
        this.propagateTaintToNewVariable(newVarName, taintedVar, sourceFile.getFilePath(), lineAndColumn, 'variable_assignment');
      }
    } else if (Node.isCallExpression(initializer)) {
      this.checkFunctionCallTaintPropagation(initializer, newVarName, sourceFile, lineAndColumn);
    }
  }

  private checkAssignmentTaintPropagation(assignment: Node, sourceFile: SourceFile): void {
    if (!Node.isBinaryExpression(assignment)) return;
    
    const left = assignment.getLeft();
    const right = assignment.getRight();
    
    if (Node.isIdentifier(left) && Node.isIdentifier(right)) {
      const targetVarName = left.getText();
      const sourceVarName = right.getText();
      const taintedVar = this.findTaintedVariableByName(sourceVarName);
      
      if (taintedVar) {
        const lineAndColumn = sourceFile.getLineAndColumnAtPos(assignment.getStart());
        this.propagateTaintToNewVariable(targetVarName, taintedVar, sourceFile.getFilePath(), lineAndColumn, 'assignment');
      }
    }
  }

  private checkFunctionCallTaintPropagation(
    callExpr: CallExpression, 
    resultVarName: string, 
    sourceFile: SourceFile, 
    lineAndColumn: { line: number; column: number }
  ): void {
    const args = callExpr.getArguments();
    
    for (const arg of args) {
      if (Node.isIdentifier(arg)) {
        const argName = arg.getText();
        const taintedVar = this.findTaintedVariableByName(argName);
        
        if (taintedVar) {
          this.propagateTaintToNewVariable(
            resultVarName, 
            taintedVar, 
            sourceFile.getFilePath(), 
            lineAndColumn, 
            'function_call'
          );
          break;
        }
      }
    }
  }

  private propagateTaintToNewVariable(
    newVarName: string, 
    originalTaint: TaintedVariable, 
    filePath: string, 
    lineAndColumn: { line: number; column: number },
    operation: string
  ): void {
    const nodeId = `${filePath}:${lineAndColumn.line}:${lineAndColumn.column}:${newVarName}`;
    const newTaintedVar: TaintedVariable = {
      name: newVarName,
      nodeId,
      sourceType: originalTaint.sourceType,
      filePath,
      line: lineAndColumn.line,
      column: lineAndColumn.column
    };
    
    this.taintedVariables.set(nodeId, newTaintedVar);
    
    const originalTrace = this.dataFlowTraces.get(originalTaint.nodeId);
    if (originalTrace) {
      this.dataFlowTraces.set(nodeId, {
        origin: originalTrace.origin,
        propagationPath: [
          ...originalTrace.propagationPath,
          {
            filePath,
            line: lineAndColumn.line,
            column: lineAndColumn.column,
            operation
          }
        ]
      });
    }
  }

  private findTaintedVariableByName(varName: string): TaintedVariable | null {
    for (const [, taintedVar] of this.taintedVariables) {
      if (taintedVar.name === varName) {
        return taintedVar;
      }
    }
    return null;
  }

  private identifyVulnerableSinks(sourceFile: SourceFile): void {
    sourceFile.forEachDescendant((node: Node) => {
      if (Node.isCallExpression(node)) {
        this.checkMongooseCall(node, sourceFile);
      }
    });
  }

  private checkMongooseCall(callExpr: CallExpression, sourceFile: SourceFile): void {
    const expression = callExpr.getExpression();
    
    if (Node.isPropertyAccessExpression(expression)) {
      const methodName = expression.getName();
      const mongooseMethods = [
        'find', 'findOne', 'findById', 'findOneAndUpdate', 'findOneAndDelete',
        'updateOne', 'updateMany', 'deleteOne', 'deleteMany', 'where', 'aggregate'
      ];
      
      if (mongooseMethods.includes(methodName)) {
        this.analyzeMongooseQuery(callExpr, methodName, sourceFile);
      }
    }
  }

  private analyzeMongooseQuery(callExpr: CallExpression, methodName: string, sourceFile: SourceFile): void {
    const args = callExpr.getArguments();
    if (args.length === 0) return;

    const lineAndColumn = sourceFile.getLineAndColumnAtPos(callExpr.getStart());

    if (methodName === 'where') {
      this.checkWhereClause(args[0], callExpr, sourceFile, lineAndColumn);
    } else {
      const queryArg = args[0];
      if (Node.isObjectLiteralExpression(queryArg)) {
        this.analyzeQueryObject(queryArg, callExpr, sourceFile, lineAndColumn);
      } else {
        this.checkDirectTaintUsage(queryArg, callExpr, sourceFile, lineAndColumn);
      }
    }
  }

  private checkWhereClause(
    whereArg: Node, 
    callExpr: CallExpression, 
    sourceFile: SourceFile, 
    lineAndColumn: { line: number; column: number }
  ): void {
    if (Node.isIdentifier(whereArg)) {
      const varName = whereArg.getText();
      const taintedVar = this.findTaintedVariableByName(varName);
      
      if (taintedVar) {
        this.reportVulnerability(
          'critical',
          '$where JavaScript Injection',
          'nosql-where-injection',
          'Tainted data used in MongoDB $where clause - allows arbitrary JavaScript execution',
          taintedVar,
          callExpr.getText(),
          sourceFile.getFilePath(),
          lineAndColumn
        );
      }
    }
  }

  private analyzeQueryObject(
    queryObj: ObjectLiteralExpression, 
    callExpr: CallExpression, 
    sourceFile: SourceFile, 
    lineAndColumn: { line: number; column: number }
  ): void {
    queryObj.getProperties().forEach(property => {
      if (Node.isPropertyAssignment(property)) {
        this.analyzePropertyAssignment(property, callExpr, sourceFile, lineAndColumn);
      }
    });
  }

  private analyzePropertyAssignment(
    property: PropertyAssignment, 
    callExpr: CallExpression, 
    sourceFile: SourceFile, 
    lineAndColumn: { line: number; column: number }
  ): void {
    const nameNode = property.getNameNode();
    const valueNode = property.getInitializer();

    if (Node.isComputedPropertyName(nameNode)) {
      const computedExpr = nameNode.getExpression();
      if (Node.isIdentifier(computedExpr)) {
        const varName = computedExpr.getText();
        const taintedVar = this.findTaintedVariableByName(varName);
        
        if (taintedVar) {
          this.reportVulnerability(
            'high',
            'Query Operator Injection',
            'nosql-operator-injection',
            'Tainted data used as MongoDB query operator - allows injection of malicious operators',
            taintedVar,
            callExpr.getText(),
            sourceFile.getFilePath(),
            lineAndColumn
          );
        }
      }
    }

    if ((Node.isStringLiteral(nameNode) && nameNode.getLiteralValue() === '$where') ||
        (Node.isIdentifier(nameNode) && nameNode.getText() === '$where')) {
      if (Node.isIdentifier(valueNode)) {
        const varName = valueNode.getText();
        const taintedVar = this.findTaintedVariableByName(varName);
        
        if (taintedVar) {
          this.reportVulnerability(
            'critical',
            '$where JavaScript Injection',
            'nosql-where-injection',
            'Tainted data used in MongoDB $where clause - allows arbitrary JavaScript execution',
            taintedVar,
            callExpr.getText(),
            sourceFile.getFilePath(),
            lineAndColumn
          );
        }
      }
    }

    if (Node.isIdentifier(valueNode)) {
      const varName = valueNode.getText();
      const taintedVar = this.findTaintedVariableByName(varName);
      
      if (taintedVar) {
        // This is generally safe but we track it for completeness - don't report as vulnerability
      }
    }
  }

  private checkDirectTaintUsage(
    arg: Node, 
    callExpr: CallExpression, 
    sourceFile: SourceFile, 
    lineAndColumn: { line: number; column: number }
  ): void {
    if (Node.isIdentifier(arg)) {
      const varName = arg.getText();
      const taintedVar = this.findTaintedVariableByName(varName);
      
      if (taintedVar) {
        // This could be dangerous if the entire query is user-controlled
        this.reportVulnerability(
          'high',
          'Direct Query Injection',
          'nosql-direct-injection',
          'Entire MongoDB query constructed from tainted data - potential for various injection attacks',
          taintedVar,
          callExpr.getText(),
          sourceFile.getFilePath(),
          lineAndColumn
        );
      }
    }
  }

  private reportVulnerability(
    severity: 'low' | 'medium' | 'high' | 'critical',
    type: string,
    ruleId: string,
    message: string,
    taintedVar: TaintedVariable,
    code: string,
    filePath: string,
    lineAndColumn: { line: number; column: number }
  ): void {
    const trace = this.dataFlowTraces.get(taintedVar.nodeId);
    let traceMessage = '';
    
    if (trace) {
      traceMessage = `\nData flow trace: Taint originated from ${trace.origin.sourceType} at ${trace.origin.filePath}:${trace.origin.line}`;
      if (trace.propagationPath.length > 0) {
        traceMessage += trace.propagationPath
          .map(step => `\n  -> ${step.operation} at ${step.filePath}:${step.line}`)
          .join('');
      }
      traceMessage += `\n  -> reached database query sink at ${filePath}:${lineAndColumn.line}`;
    }

    const finding: SecurityFinding = {
      filePath,
      line: lineAndColumn.line,
      column: lineAndColumn.column,
      message: `${type}: ${message}${traceMessage}`,
      code,
      severity,
      ruleId,
    };

    this.addFinding(finding);
  }
}
