import * as path from 'path';
import * as fs from 'fs';
import { DangerousInnerHTMLChecker } from './scans/dangerous-html-checker';
import { JwtDecodeChecker } from './scans/jwt-decode-checker';
import { NoSQLInjectionChecker } from './scans/nosql-injection-checker';
import { CheckerResult } from './types';

export * from './checkers';

export function checkDangerousInnerHTML(codebasePath: string): CheckerResult {
  if (!fs.existsSync(codebasePath)) {
    throw new Error(`Codebase path does not exist: ${codebasePath}`);
  }

  const checker = new DangerousInnerHTMLChecker({ codebasePath });
  return checker.check();
}

export function checkJwtDecodeWithoutVerify(codebasePath: string): CheckerResult {
  if (!fs.existsSync(codebasePath)) {
    throw new Error(`Codebase path does not exist: ${codebasePath}`);
  }

  const checker = new JwtDecodeChecker({ codebasePath });
  return checker.check();
}

export function checkNoSQLInjection(codebasePath: string): CheckerResult {
  if (!fs.existsSync(codebasePath)) {
    throw new Error(`Codebase path does not exist: ${codebasePath}`);
  }

  const checker = new NoSQLInjectionChecker({ codebasePath });
  return checker.check();
}

export function main(): void {
  const args = process.argv.slice(2);
  
  if (args.length === 0) {
    console.error('Usage: npm run dev <codebase-path> [checker]');
    console.error('Available checkers: dangerous-html, jwt-decode, nosql-injection, all');
    process.exit(1);
  }

  const codebasePath = path.resolve(args[0]);
  const checkerType = args[1] || 'all';
  
  try {
    console.log(`Initializing TypeScript language server for: ${codebasePath}`);
    
    let totalFindings = 0;
    let totalFiles = 0;
    let filesWithFindings = 0;

    if (checkerType === 'dangerous-html' || checkerType === 'all') {
      console.log('Checking for dangerouslySetInnerHTML usage...\n');
      
      const result = checkDangerousInnerHTML(codebasePath);
      totalFiles = result.totalFiles;
      filesWithFindings = Math.max(filesWithFindings, result.filesWithFindings);
      totalFindings += result.findings.length;
      
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
      console.log('');
    }

    if (checkerType === 'nosql-injection' || checkerType === 'all') {
      console.log('Checking for NoSQL injection vulnerabilities...\n');
      
      const result = checkNoSQLInjection(codebasePath);
      totalFiles = result.totalFiles;
      filesWithFindings = Math.max(filesWithFindings, result.filesWithFindings);
      totalFindings += result.findings.length;
      
      if (result.findings.length === 0) {
        console.log('✅ No NoSQL injection vulnerabilities found!');
      } else {
        console.log(`🔴 Found ${result.findings.length} NoSQL injection vulnerabilities:\n`);
        
        result.findings.forEach((finding, index) => {
          const severityIcon = finding.severity === 'critical' ? '🚨' : finding.severity === 'high' ? '⚠️' : '⚡';
          console.log(`${index + 1}. ${severityIcon} ${finding.severity?.toUpperCase()} - ${path.relative(codebasePath, finding.filePath)}:${finding.line}:${finding.column}`);
          console.log(`   ${finding.message}`);
          console.log(`   Code: ${finding.code}\n`);
        });
      }
      console.log('');
    }

    if (checkerType === 'jwt-decode' || checkerType === 'all') {
      console.log('Checking for JWT decode without verify...\n');
      
      const result = checkJwtDecodeWithoutVerify(codebasePath);
      totalFiles = result.totalFiles;
      filesWithFindings = Math.max(filesWithFindings, result.filesWithFindings);
      totalFindings += result.findings.length;
      
      if (result.findings.length === 0) {
        console.log('✅ No JWT decode without verify issues found!');
      } else {
        console.log(`⚠️  Found ${result.findings.length} JWT decode without verify issues:\n`);
        
        result.findings.forEach((finding, index) => {
          console.log(`${index + 1}. ${path.relative(codebasePath, finding.filePath)}:${finding.line}:${finding.column}`);
          console.log(`   ${finding.message}`);
          console.log(`   Code: ${finding.code}\n`);
        });
      }
    }
    
    console.log(`Summary:`);
    console.log(`- Total files scanned: ${totalFiles}`);
    console.log(`- Files with findings: ${filesWithFindings}`);
    console.log(`- Total findings: ${totalFindings}`);
    
  } catch (error) {
    console.error('Error:', (error as Error).message);
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}
