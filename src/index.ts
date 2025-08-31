import * as path from 'path';
import * as fs from 'fs';
import { DangerousInnerHTMLChecker } from './dangerous-html-checker';
import { CheckerResult } from './types';

export * from './checkers';

export function checkDangerousInnerHTML(codebasePath: string): CheckerResult {
  if (!fs.existsSync(codebasePath)) {
    throw new Error(`Codebase path does not exist: ${codebasePath}`);
  }

  const checker = new DangerousInnerHTMLChecker({ codebasePath });
  return checker.check();
}

export function main(): void {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.error('Usage: npm run dev <codebase-path>');
    process.exit(1);
  }

  const codebasePath = path.resolve(args[0]);
  
  try {
    console.log(`Initializing TypeScript language server for: ${codebasePath}`);
    console.log('Checking for dangerouslySetInnerHTML usage...\n');
    
    const result = checkDangerousInnerHTML(codebasePath);
    
    if (result.findings.length === 0) {
      console.log('✅ No dangerouslySetInnerHTML usage found!');
    } else {
      console.log(`⚠️  Found ${result.findings.length} instances of dangerouslySetInnerHTML:\n`);
      
      result.findings.forEach((finding, index) => {
        console.log(`${index + 1}. ${path.relative(codebasePath, finding.filePath)}:${finding.line}:${finding.column}`);
        console.log(`   ${finding.message}`);
        console.log(`   Code: ${finding.code}\n`);
      });
    }
    
    console.log(`Summary:`);
    console.log(`- Total files scanned: ${result.totalFiles}`);
    console.log(`- Files with findings: ${result.filesWithFindings}`);
    console.log(`- Total findings: ${result.findings.length}`);
    
  } catch (error) {
    console.error('Error:', (error as Error).message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
