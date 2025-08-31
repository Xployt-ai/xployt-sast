# SAST Architecture

## Overview
This SAST tool is now built with a modular architecture that makes it easy to add new security checkers.

## Core Components

### `types.ts`
Defines shared interfaces:
- `SecurityFinding`: Represents a security issue found in code
- `CheckerResult`: Contains findings and metadata from a checker run
- `BaseCheckerOptions`: Configuration options for checkers

### `ts-server.ts`
Handles TypeScript project setup and file management:
- Finds and loads tsconfig.json
- Adds source files to the project
- Provides access to the ts-morph Project instance

### `base-checker.ts`
Abstract base class for all security checkers:
- Manages TypeScript server initialization
- Provides common checking workflow
- Handles finding collection and result formatting

## Available Checkers

### `dangerous-html-checker.ts`
Detects usage of `dangerouslySetInnerHTML` which can lead to XSS vulnerabilities.

### `console-log-checker.ts`
Finds `console.log` statements that should be removed in production.

## Adding New Checkers

To add a new checker:

1. Create a new file extending `BaseChecker`
2. Implement the `checkFile(sourceFile)` method
3. Use `this.addFinding()` to report issues
4. Export from `checkers/index.ts`

Example:
```typescript
export class MyChecker extends BaseChecker {
  protected checkFile(sourceFile: any): void {
    // Implementation here
  }
}
```

## Usage

```typescript
import { DangerousInnerHTMLChecker, ConsoleLogChecker } from './checkers';

const checker = new DangerousInnerHTMLChecker({ codebasePath: './src' });
const result = checker.check();
```
