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
      this.project.addSourceFilesAtPaths(pattern);
    }
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
