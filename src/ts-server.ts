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
    const extensions = ['**/*.tsx', '**/*.jsx', '**/*.ts', '**/*.js'];
    
    for (const extension of extensions) {
      const pattern = path.join(codebasePath, extension);
      try {
        this.project.addSourceFilesAtPaths(pattern);
      } catch (error) {
        // Continue with other patterns if one fails
      }
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
        
        if (entry.isDirectory() && entry.name !== 'node_modules') {
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
