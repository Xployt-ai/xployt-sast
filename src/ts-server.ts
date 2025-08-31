import { Project } from 'ts-morph';
import * as path from 'path';
import * as fs from 'fs';

export class TypeScriptServer {
  private project: Project;
  private codebasePath: string;

  constructor(codebasePath: string) {
    this.codebasePath = codebasePath;
    const tsConfigPath = this.findTsConfig(codebasePath);
    this.project = new Project({
      tsConfigFilePath: tsConfigPath,
    });
    
    this.addSourceFiles(codebasePath);
  }

  private findTsConfig(codebasePath: string): string | undefined {
    const tsConfigPath = path.join(codebasePath, 'tsconfig.json');
    if (fs.existsSync(tsConfigPath)) {
      return tsConfigPath;
    }
    return undefined;
  }

  private addSourceFiles(codebasePath: string): void {
    const includePatterns = [
      path.join(codebasePath, '**/*.tsx'),
      path.join(codebasePath, '**/*.jsx'),
      path.join(codebasePath, '**/*.ts'),
      path.join(codebasePath, '**/*.js'),
    ];

    const excludePatterns = [
      '!' + path.join(codebasePath, '**/node_modules/**'),
      '!' + path.join(codebasePath, '**/dist/**'),
      '!' + path.join(codebasePath, '**/coverage/**'),
      '!' + path.join(codebasePath, '**/.git/**'),
      '!' + path.join(codebasePath, '**/build/**'),
      '!' + path.join(codebasePath, '**/.next/**'),
      '!' + path.join(codebasePath, '**/out/**'),
    ];

    try {
      this.project.addSourceFilesAtPaths([...includePatterns, ...excludePatterns]);
    } catch (error) {
      // Continue with direct add if glob pattern fails
    }
    
    // If no files were added through patterns, try to add files directly
    if (this.project.getSourceFiles().length === 0) {
      this.addSourceFilesDirectly(codebasePath);
    }
  }

  private addSourceFilesDirectly(codebasePath: string): void {
    const addFilesRecursively = (dir: string) => {
      if (!fs.existsSync(dir)) return;
      
      const entries = fs.readdirSync(dir, { withFileTypes: true });
      
      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        
        if (
          entry.isDirectory() &&
          !['node_modules', 'dist', 'coverage', '.git', 'build', '.next', 'out'].includes(entry.name)
        ) {
          addFilesRecursively(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name);
          if (['.ts', '.tsx', '.js', '.jsx'].includes(ext)) {
            try {
              this.project.addSourceFileAtPath(fullPath);
            } catch (error) {
              // Continue with other files if one fails
            }
          }
        }
      }
    };
    
    addFilesRecursively(codebasePath);
  }

  public getProject(): Project {
    return this.project;
  }

  public getSourceFiles() {
    return this.project.getSourceFiles();
  }

  public getCodebasePath(): string {
    return this.codebasePath;
  }
}
