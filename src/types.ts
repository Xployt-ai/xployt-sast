export interface SecurityFinding {
  filePath: string;
  line: number;
  column: number;
  message: string;
  code: string;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  ruleId?: string;
}

export interface CheckerResult {
  findings: SecurityFinding[];
  totalFiles: number;
  filesWithFindings: number;
}

export interface BaseCheckerOptions {
  codebasePath: string;
  extensions?: string[];
}
