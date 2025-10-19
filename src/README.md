# SAST Architecture

## Overview
This SAST tool is built with a modular architecture that makes it easy to add new security checkers. All scanners are organized in the `scans/` directory with comprehensive unit tests.

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

### `scans/base-checker.ts`
Abstract base class for all security checkers:
- Manages TypeScript server initialization
- Provides common checking workflow
- Handles finding collection and result formatting

## Available Checkers

### `scans/dangerous-html-checker.ts`
Detects usage of `dangerouslySetInnerHTML` which can lead to XSS vulnerabilities.
**Strategy**: Traverses JSX attributes and flags any named `dangerouslySetInnerHTML`.

### `scans/console-log-checker.ts`
Finds `console.log` statements that should be removed in production.
**Strategy**: Identifies property access expressions where object is `console` and property is `log`.

### `scans/jwt-decode-checker.ts`
Detects JWT decode operations without corresponding verification in the same function scope.
**Strategy**: Finds `jwt.decode` calls, locates containing function, then checks if same token is verified with `jwt.verify` within that scope.

## Adding New Checkers

To add a new checker:

1. Create a new file in `scans/` extending `BaseChecker`
2. Implement the `checkFile(sourceFile)` method
3. Use `this.addFinding()` to report issues
4. Export from `checkers/index.ts`
5. Write comprehensive unit tests in `__tests__/scans/`

Example:
```typescript
export class MyChecker extends BaseChecker {
  protected checkFile(sourceFile: any): void {
    // Implementation here
  }
}
```

## Testing

The project includes comprehensive unit tests for all checkers:

- Run tests: `npm test`
- Run with coverage: `npm run test:coverage`
- Watch mode: `npm run test:watch`

All checkers have 90%+ test coverage with tests for:
- Positive cases (finding security issues)
- Negative cases (not flagging safe code)
- Edge cases and error handling
- File path and line number accuracy

## Usage

```typescript
import { DangerousInnerHTMLChecker, ConsoleLogChecker, JwtDecodeChecker } from './checkers';

const checker = new DangerousInnerHTMLChecker({ codebasePath: './src' });
const result = checker.check();

// Or use the convenience functions
import { checkDangerousInnerHTML, checkJwtDecodeWithoutVerify } from './index';
const jwtResult = checkJwtDecodeWithoutVerify('./src');
```

# Docker

```
docker build -t xployt-sast-scanner .
```

```
docker run 
-p 8001:8001
-v /Users/lakshith/Developer/xployt-ai/xployt-main-server/local_storage:/app/local_storage \
 xployt-sast-scanner
```