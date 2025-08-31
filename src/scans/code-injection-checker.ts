import { 
  Node, 
  CallExpression, 
  NewExpression,
  VariableDeclaration, 
  PropertyAccessExpression,
  Identifier,
  ObjectBindingPattern,
  ArrayBindingPattern,
  BindingElement,
  StringLiteral,
  SourceFile,
  SyntaxKind
} from 'ts-morph';
import { BaseChecker } from './base-checker';
import { SecurityFinding, BaseCheckerOptions } from '../types';

interface TaintedVariable {
  name: string;
  nodeId: string;
  sourceType: 'req.params' | 'req.query' | 'req.body' | 'req.headers' | 'window.location' | 'document.cookie' | 'postMessage' | 'input.value' | 'api.response';
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

export class CodeInjectionChecker extends BaseChecker {
  private taintedVariables = new Map<string, TaintedVariable>();
  private dataFlowTraces = new Map<string, DataFlowTrace>();
  
  constructor(options: BaseCheckerOptions) {
    super(options);
  }

  protected checkFile(sourceFile: SourceFile): void {
    if (this.verbose) console.log(`[CodeInj] start file: ${sourceFile.getFilePath()}`);
    this.identifyTaintSources(sourceFile);
    this.propagateTaint(sourceFile);
    this.identifyVulnerableSinks(sourceFile);
    if (this.verbose)
      console.log(
        `[CodeInj] end file: ${sourceFile.getFilePath()} (tainted=${this.taintedVariables.size}, findings=${this.findings.length})`
      );
  }

  private identifyTaintSources(sourceFile: SourceFile): void {
    sourceFile.forEachDescendant((node: Node) => {
      if (Node.isCallExpression(node)) {
        this.checkExpressRoute(node, sourceFile);
        this.checkPromiseChain(node, sourceFile);
      }
      if (Node.isVariableDeclaration(node)) {
        this.checkClientSideTaintSources(node, sourceFile);
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
        if (this.verbose) console.log(`[CodeInj] route handler found: req param "${reqParamName}" in ${sourceFile.getFilePath()}`);
        this.findTaintSourcesInFunction(handlerArg, reqParamName, sourceFile);
      }
    }
  }

  private checkClientSideTaintSources(varDecl: VariableDeclaration, sourceFile: SourceFile): void {
    const initializer = varDecl.getInitializer();
    if (!initializer) return;

    const nameNode = varDecl.getNameNode();
    const taintInfo = this.analyzeClientSideTaintSource(initializer);
    
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

  private checkPromiseChain(callExpr: CallExpression, sourceFile: SourceFile): void {
    const expression = callExpr.getExpression();
    
    if (Node.isPropertyAccessExpression(expression)) {
      const methodName = expression.getName();
      if (methodName === 'then') {
        if (this.verbose) {
          console.log(`[CodeInj] Found .then() call: ${callExpr.getText()}`);
        }
        
        const args = callExpr.getArguments();
        if (args.length > 0) {
          const callback = args[0];
          if (Node.isArrowFunction(callback) || Node.isFunctionExpression(callback)) {
            const parameters = callback.getParameters();
            if (parameters.length > 0) {
              const param = parameters[0];
              const paramName = param.getName();
              const lineAndColumn = sourceFile.getLineAndColumnAtPos(param.getStart());
              
              if (this.verbose) {
                console.log(`[CodeInj] .then() callback parameter: ${paramName}`);
              }
              
              const isApiContext = this.isApiResponseContext(expression);
              if (this.verbose) {
                console.log(`[CodeInj] Is API response context: ${isApiContext}`);
              }
              
              // Also check if this .then() follows another .then() that returns json() or text()
              let isChainedApiContext = false;
              const callChainText = callExpr.getText();
              if (callChainText.includes('.json()') || callChainText.includes('.text()')) {
                isChainedApiContext = true;
                if (this.verbose) {
                  console.log(`[CodeInj] Found chained API context in: ${callChainText}`);
                }
              }
              
              if (isApiContext || isChainedApiContext) {
                if (this.verbose) {
                  console.log(`[CodeInj] Registering ${paramName} as tainted from api.response`);
                }
                this.registerTaintedVariable(paramName, 'api.response', sourceFile.getFilePath(), lineAndColumn);
              }
            }
          }
        }
      }
    }
  }

  private isApiResponseContext(expression: PropertyAccessExpression): boolean {
    const objectExpr = expression.getExpression();
    
    // Check if this is a direct call to response.json() or response.text()
    if (Node.isCallExpression(objectExpr)) {
      const innerExpression = objectExpr.getExpression();
      if (Node.isPropertyAccessExpression(innerExpression)) {
        const methodName = innerExpression.getName();
        return methodName === 'json' || methodName === 'text';
      }
    }
    
    // Check if this is a chained .then() after a .json() or .text() call
    // Look at the full call chain to see if it contains json() or text()
    const fullText = objectExpr.getText();
    if (this.verbose) {
      console.log(`[CodeInj] Checking API context for: ${fullText}`);
    }
    
    const hasJsonOrText = fullText.includes('.json()') || fullText.includes('.text()');
    if (this.verbose) {
      console.log(`[CodeInj] Contains .json() or .text(): ${hasJsonOrText}`);
    }
    
    return hasJsonOrText;
  }

  private analyzeClientSideTaintSource(node: Node): TaintedVariable['sourceType'] | null {
    const nodeText = node.getText();
    
    if (nodeText.includes('window.location') || nodeText.includes('location.hash') || 
        nodeText.includes('location.search') || nodeText.includes('location.pathname')) {
      return 'window.location';
    }
    if (nodeText.includes('document.cookie')) return 'document.cookie';
    if (nodeText.includes('.value') && nodeText.includes('input')) return 'input.value';
    if (nodeText.includes('postMessage') || nodeText.includes('event.data')) return 'postMessage';
    
    if (Node.isCallExpression(node)) {
      const expression = node.getExpression();
      if (Node.isPropertyAccessExpression(expression)) {
        const methodName = expression.getName();
        if (methodName === 'json' || methodName === 'text') {
          return 'api.response';
        }
      }
    }
    
    return null;
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
    const taintInfo = this.analyzeServerSideTaintSource(initializer, reqParamName);
    
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

  private analyzeServerSideTaintSource(node: Node, reqParamName: string): TaintedVariable['sourceType'] | null {
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
    
    if (this.verbose) {
      console.log(`[CodeInj] Registered tainted variable: ${name} (${sourceType}) at ${filePath}:${lineAndColumn.line}`);
    }
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
          this.registerTaintedVariable(name, sourceType, filePath, lineAndColumn);
        }
      }
    });
  }

  private propagateTaint(sourceFile: SourceFile): void {
    let changed = true;
    while (changed) {
      changed = false;
      const oldSize = this.taintedVariables.size;
      
      sourceFile.forEachDescendant((node: Node) => {
        if (Node.isVariableDeclaration(node)) {
          this.checkTaintPropagation(node, sourceFile);
        } else if (Node.isBinaryExpression(node) && node.getOperatorToken().getKind() === SyntaxKind.EqualsToken) {
          this.checkAssignmentTaintPropagation(node, sourceFile);
        }
      });
      
      if (this.taintedVariables.size > oldSize) {
        changed = true;
      }
    }
  }

  private checkTaintPropagation(varDecl: VariableDeclaration, sourceFile: SourceFile): void {
    const initializer = varDecl.getInitializer();
    if (!initializer) return;

    const nameNode = varDecl.getNameNode();
    if (!Node.isIdentifier(nameNode)) return;

    const newVarName = nameNode.getText();
    const lineAndColumn = sourceFile.getLineAndColumnAtPos(varDecl.getStart());

    if (this.findTaintedVariableByName(newVarName)) {
      return;
    }

    if (this.verbose) {
      console.log(`[CodeInj] Checking taint propagation for variable: ${newVarName}, initializer: ${initializer.getKindName()}`);
    }

    if (Node.isIdentifier(initializer)) {
      const sourceVarName = initializer.getText();
      const taintedVar = this.findTaintedVariableByName(sourceVarName);
      
      if (taintedVar) {
        this.propagateTaintToNewVariable(newVarName, taintedVar, sourceFile.getFilePath(), lineAndColumn, 'variable_assignment');
      }
    } else if (Node.isCallExpression(initializer)) {
      this.checkFunctionCallTaintPropagation(initializer, newVarName, sourceFile, lineAndColumn);
    } else if (Node.isBinaryExpression(initializer)) {
      if (this.verbose) {
        console.log(`[CodeInj] Checking binary expression taint propagation for: ${newVarName}`);
      }
      this.checkBinaryExpressionTaintPropagation(initializer, newVarName, sourceFile, lineAndColumn);
    } else if (Node.isTemplateExpression(initializer)) {
      this.checkTemplateExpressionTaintPropagation(initializer, newVarName, sourceFile, lineAndColumn);
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

    const expression = callExpr.getExpression();
    if (Node.isPropertyAccessExpression(expression)) {
      const objectExpr = expression.getExpression();
      if (Node.isIdentifier(objectExpr)) {
        const objectName = objectExpr.getText();
        const taintedVar = this.findTaintedVariableByName(objectName);
        
        if (taintedVar) {
          this.propagateTaintToNewVariable(
            resultVarName, 
            taintedVar, 
            sourceFile.getFilePath(), 
            lineAndColumn, 
            'function_call'
          );
        }
      }
    }
  }

  private checkBinaryExpressionTaintPropagation(
    binaryExpr: Node,
    resultVarName: string,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    if (!Node.isBinaryExpression(binaryExpr)) return;
    
    const left = binaryExpr.getLeft();
    const right = binaryExpr.getRight();
    
    if (this.verbose) {
      console.log(`[CodeInj] Binary expression - left: ${left.getKindName()} (${left.getText()}), right: ${right.getKindName()} (${right.getText()})`);
    }
    
    const checkOperand = (operand: Node): boolean => {
      if (Node.isIdentifier(operand)) {
        const varName = operand.getText();
        const taintedVar = this.findTaintedVariableByName(varName);
        if (this.verbose) {
          console.log(`[CodeInj] Checking operand ${varName}, tainted: ${taintedVar ? 'yes' : 'no'}`);
        }
        if (taintedVar) {
          if (this.verbose) {
            console.log(`[CodeInj] Propagating taint from ${varName} to ${resultVarName}`);
          }
          this.propagateTaintToNewVariable(
            resultVarName,
            taintedVar,
            sourceFile.getFilePath(),
            lineAndColumn,
            'string_concatenation'
          );
          return true;
        }
      } else if (Node.isBinaryExpression(operand)) {
        // Recursively check nested binary expressions
        if (this.verbose) {
          console.log(`[CodeInj] Recursively checking nested binary expression: ${operand.getText()}`);
        }
        return checkOperand(operand.getLeft()) || checkOperand(operand.getRight());
      }
      return false;
    };
    
    checkOperand(left) || checkOperand(right);
  }

  private checkTemplateExpressionTaintPropagation(
    templateExpr: Node,
    resultVarName: string,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    if (!Node.isTemplateExpression(templateExpr)) return;
    
    templateExpr.getTemplateSpans().forEach(span => {
      const expression = span.getExpression();
      if (Node.isIdentifier(expression)) {
        const varName = expression.getText();
        const taintedVar = this.findTaintedVariableByName(varName);
        if (taintedVar) {
          this.propagateTaintToNewVariable(
            resultVarName,
            taintedVar,
            sourceFile.getFilePath(),
            lineAndColumn,
            'template_literal'
          );
        }
      }
    });
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
        this.checkCodeExecutionSinks(node, sourceFile);
      } else if (Node.isNewExpression(node)) {
        this.checkNewExpressionSinks(node, sourceFile);
      } else if (Node.isBinaryExpression(node) && node.getOperatorToken().getKind() === SyntaxKind.EqualsToken) {
        this.checkAssignmentSinks(node, sourceFile);
      }
    });
  }

  private checkCodeExecutionSinks(callExpr: CallExpression, sourceFile: SourceFile): void {
    const expression = callExpr.getExpression();
    const lineAndColumn = sourceFile.getLineAndColumnAtPos(callExpr.getStart());
    
    if (Node.isIdentifier(expression)) {
      const functionName = expression.getText();
      this.checkDirectFunctionCall(functionName, callExpr, sourceFile, lineAndColumn);
    } else if (Node.isPropertyAccessExpression(expression)) {
      const objectExpr = expression.getExpression();
      const methodName = expression.getName();
      this.checkMethodCall(objectExpr, methodName, callExpr, sourceFile, lineAndColumn);
    }
  }

  private checkDirectFunctionCall(
    functionName: string,
    callExpr: CallExpression,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    const args = callExpr.getArguments();
    if (args.length === 0) return;

    switch (functionName) {
      case 'eval':
        this.checkEvalCall(args[0], callExpr, sourceFile, lineAndColumn);
        break;
      case 'setTimeout':
      case 'setInterval':
        this.checkTimerFunction(functionName, args[0], callExpr, sourceFile, lineAndColumn);
        break;
    }
  }

  private checkNewExpressionSinks(newExpr: Node, sourceFile: SourceFile): void {
    if (!Node.isNewExpression(newExpr)) return;
    
    const expression = newExpr.getExpression();
    const lineAndColumn = sourceFile.getLineAndColumnAtPos(newExpr.getStart());
    
    if (Node.isIdentifier(expression) && expression.getText() === 'Function') {
      const args = newExpr.getArguments();
      this.checkFunctionConstructor(args, newExpr, sourceFile, lineAndColumn);
    }
  }

  private checkAssignmentSinks(assignment: Node, sourceFile: SourceFile): void {
    if (!Node.isBinaryExpression(assignment)) return;
    
    const left = assignment.getLeft();
    const right = assignment.getRight();
    const lineAndColumn = sourceFile.getLineAndColumnAtPos(assignment.getStart());
    
    if (Node.isPropertyAccessExpression(left)) {
      const propertyName = left.getName();
      if (propertyName === 'innerHTML' || propertyName === 'outerHTML') {
        this.checkInnerHTMLAssignment(right, assignment, sourceFile, lineAndColumn);
      }
    }
  }

  private checkMethodCall(
    objectExpr: Node,
    methodName: string,
    callExpr: CallExpression,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    const args = callExpr.getArguments();
    
    if (methodName === 'setAttribute' && args.length >= 2) {
      this.checkSetAttributeCall(args, callExpr, sourceFile, lineAndColumn);
    }
  }

  private checkEvalCall(
    arg: Node,
    callExpr: CallExpression,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    if (this.verbose) {
      console.log(`[CodeInj] Checking eval() call with arg: ${arg.getText()}`);
    }
    
    if (Node.isIdentifier(arg)) {
      const varName = arg.getText();
      const taintedVar = this.findTaintedVariableByName(varName);
      
      if (this.verbose) {
        console.log(`[CodeInj] Looking for tainted variable: ${varName}, found: ${taintedVar ? 'yes' : 'no'}`);
      }
      
      if (taintedVar) {
        this.reportVulnerability(
          'critical',
          'Code Injection via eval()',
          'code-injection-eval',
          'Tainted data passed to eval() - allows arbitrary JavaScript execution',
          taintedVar,
          callExpr.getText(),
          sourceFile.getFilePath(),
          lineAndColumn
        );
      }
    } else if (Node.isPropertyAccessExpression(arg)) {
      // Handle cases like eval(data.script) where data is tainted
      const objectExpr = arg.getExpression();
      if (Node.isIdentifier(objectExpr)) {
        const varName = objectExpr.getText();
        const taintedVar = this.findTaintedVariableByName(varName);
        
        if (this.verbose) {
          console.log(`[CodeInj] Looking for tainted object: ${varName}, found: ${taintedVar ? 'yes' : 'no'}`);
        }
        
        if (taintedVar) {
          this.reportVulnerability(
            'critical',
            'Code Injection via eval()',
            'code-injection-eval',
            'Tainted data passed to eval() - allows arbitrary JavaScript execution',
            taintedVar,
            callExpr.getText(),
            sourceFile.getFilePath(),
            lineAndColumn
          );
        }
      }
    } else if (Node.isStringLiteral(arg) || Node.isTemplateExpression(arg) || Node.isBinaryExpression(arg)) {
      if (this.verbose) {
        console.log(`[CodeInj] Checking complex expression for taint: ${arg.getKindName()}`);
      }
      this.checkComplexExpressionForTaint(arg, 'eval()', 'critical', 'code-injection-eval', callExpr, sourceFile, lineAndColumn);
    }
  }

  private checkFunctionConstructor(
    args: Node[],
    expr: Node,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    const lastArg = args[args.length - 1];
    if (!lastArg) return;

    if (Node.isIdentifier(lastArg)) {
      const varName = lastArg.getText();
      const taintedVar = this.findTaintedVariableByName(varName);
      
      if (taintedVar) {
        this.reportVulnerability(
          'critical',
          'Code Injection via Function Constructor',
          'code-injection-function',
          'Tainted data passed to Function constructor - allows arbitrary JavaScript execution',
          taintedVar,
          expr.getText(),
          sourceFile.getFilePath(),
          lineAndColumn
        );
      }
    } else {
      this.checkComplexExpressionForTaint(lastArg, 'Function constructor', 'critical', 'code-injection-function', expr, sourceFile, lineAndColumn);
    }
  }

  private checkTimerFunction(
    functionName: string,
    arg: Node,
    callExpr: CallExpression,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    if (Node.isIdentifier(arg)) {
      const varName = arg.getText();
      const taintedVar = this.findTaintedVariableByName(varName);
      
      if (taintedVar) {
        this.reportVulnerability(
          'high',
          `Code Injection via ${functionName}()`,
          `code-injection-${functionName.toLowerCase()}`,
          `Tainted data passed to ${functionName}() as string - allows code execution`,
          taintedVar,
          callExpr.getText(),
          sourceFile.getFilePath(),
          lineAndColumn
        );
      }
    } else if (Node.isStringLiteral(arg) || Node.isTemplateExpression(arg) || Node.isBinaryExpression(arg)) {
      this.checkComplexExpressionForTaint(arg, `${functionName}()`, 'high', `code-injection-${functionName.toLowerCase()}`, callExpr, sourceFile, lineAndColumn);
    }
  }

  private checkSetAttributeCall(
    args: Node[],
    callExpr: CallExpression,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    const attributeArg = args[0];
    const valueArg = args[1];
    
    if (Node.isStringLiteral(attributeArg)) {
      const attributeName = attributeArg.getLiteralValue();
      if (attributeName.startsWith('on')) {
        if (Node.isIdentifier(valueArg)) {
          const varName = valueArg.getText();
          const taintedVar = this.findTaintedVariableByName(varName);
          
          if (taintedVar) {
            this.reportVulnerability(
              'high',
              'Code Injection via Event Handler',
              'code-injection-event-handler',
              `Tainted data used in ${attributeName} event handler - allows JavaScript execution`,
              taintedVar,
              callExpr.getText(),
              sourceFile.getFilePath(),
              lineAndColumn
            );
          }
        } else {
          this.checkComplexExpressionForTaint(valueArg, 'event handler', 'high', 'code-injection-event-handler', callExpr, sourceFile, lineAndColumn);
        }
      }
    }
  }

  private checkInnerHTMLAssignment(
    arg: Node,
    expr: Node,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    if (Node.isIdentifier(arg)) {
      const varName = arg.getText();
      const taintedVar = this.findTaintedVariableByName(varName);
      
      if (taintedVar) {
        this.reportVulnerability(
          'high',
          'Code Injection via innerHTML',
          'code-injection-innerhtml',
          'Tainted data assigned to innerHTML - allows script injection and XSS',
          taintedVar,
          expr.getText(),
          sourceFile.getFilePath(),
          lineAndColumn
        );
      }
    } else {
      this.checkComplexExpressionForTaint(arg, 'innerHTML', 'high', 'code-injection-innerhtml', expr, sourceFile, lineAndColumn);
    }
  }

  private checkComplexExpressionForTaint(
    expr: Node,
    sinkType: string,
    severity: 'low' | 'medium' | 'high' | 'critical',
    ruleId: string,
    parentExpr: Node,
    sourceFile: SourceFile,
    lineAndColumn: { line: number; column: number }
  ): void {
    const taintedVars: TaintedVariable[] = [];
    
    const findTaintInExpression = (node: Node) => {
      if (Node.isIdentifier(node)) {
        const varName = node.getText();
        const taintedVar = this.findTaintedVariableByName(varName);
        if (taintedVar) {
          taintedVars.push(taintedVar);
        }
      } else if (Node.isTemplateExpression(node)) {
        node.getTemplateSpans().forEach(span => {
          findTaintInExpression(span.getExpression());
        });
      } else if (Node.isBinaryExpression(node)) {
        findTaintInExpression(node.getLeft());
        findTaintInExpression(node.getRight());
      }
    };
    
    findTaintInExpression(expr);
    
    taintedVars.forEach(taintedVar => {
      this.reportVulnerability(
        severity,
        `Code Injection via ${sinkType}`,
        ruleId,
        `Tainted data used in ${sinkType} - allows code execution`,
        taintedVar,
        parentExpr.getText(),
        sourceFile.getFilePath(),
        lineAndColumn
      );
    });
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
      traceMessage += `\n  -> reached code execution sink at ${filePath}:${lineAndColumn.line}`;
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
