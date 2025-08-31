# SAST Scanning Strategies

## Overview
This document outlines the specific strategies used by each security checker in the SAST tool. All scanners are located in the `src/scans/` directory and have comprehensive unit test coverage.

## Checker Strategies

### Dangerous Inner HTML Checker (`scans/dangerous-html-checker.ts`)
**Target**: React `dangerouslySetInnerHTML` attribute usage
**Strategy**: Traverses all JSX attributes in the AST and flags any attribute with the exact name `dangerouslySetInnerHTML`. Simple syntactic pattern matching on JSX elements.
**Test Coverage**: 100% - Tests positive/negative cases, nested components, and line accuracy.

### Console Log Checker (`scans/console-log-checker.ts`)
**Target**: `console.log` statements in production code
**Strategy**: Identifies call expressions with property access pattern where the object is `console` and the property is `log`. Checks for both direct calls and method invocations.
**Test Coverage**: 100% - Tests various argument patterns, different contexts, and excludes other console methods.

### JWT Decode Without Verify Checker (`scans/jwt-decode-checker.ts`)
**Target**: JWT tokens decoded without verification in the same function scope
**Strategy**: Multi-step analysis - first finds all `jwt.decode` or `jsonwebtoken.decode` calls, then locates the containing function scope, and finally searches within that scope for corresponding `jwt.verify` calls on the same token variable. Uses control flow analysis within function boundaries.
**Test Coverage**: 90%+ - Tests function scope analysis, variable tracking, nested functions, and different import patterns.

## Implementation Patterns

All checkers follow the same architectural pattern:
1. Extend `BaseChecker` abstract class (located in `scans/base-checker.ts`)
2. Implement `checkFile(sourceFile)` method
3. Use AST traversal with `forEachDescendant`
4. Report findings via `addFinding()` method
5. Include severity levels and rule IDs for categorization
6. Have comprehensive unit tests in `__tests__/scans/`

## Testing Strategy

Each checker includes tests for:
- **Positive cases**: Correctly identifying security issues
- **Negative cases**: Not flagging safe code patterns
- **Edge cases**: Complex scenarios and error conditions
- **Accuracy**: Correct file paths, line numbers, and column positions
- **Multiple instances**: Handling multiple findings in single files
- **Different contexts**: Various function types, scopes, and syntactic patterns
