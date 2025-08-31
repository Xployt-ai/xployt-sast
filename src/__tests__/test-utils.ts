import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

export class TestProjectHelper {
  private tempDir: string;
  private createdFiles: string[] = [];

  constructor() {
    this.tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sast-test-'));
    this.createTsConfig();
  }

  createTestFile(fileName: string, content: string): string {
    const filePath = path.join(this.tempDir, fileName);
    const dir = path.dirname(filePath);
    
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    
    fs.writeFileSync(filePath, content);
    this.createdFiles.push(filePath);
    return filePath;
  }

  createTsConfig(): void {
    const tsConfigContent = {
      compilerOptions: {
        target: 'ES2018',
        module: 'commonjs',
        lib: ['ES2018', 'DOM'],
        strict: false,
        esModuleInterop: true,
        skipLibCheck: true,
        forceConsistentCasingInFileNames: true,
        jsx: 'react',
        moduleResolution: 'node',
        allowJs: true
      },
      include: ['**/*'],
      exclude: ['node_modules']
    };
    
    fs.writeFileSync(
      path.join(this.tempDir, 'tsconfig.json'),
      JSON.stringify(tsConfigContent, null, 2)
    );
  }

  getTempDir(): string {
    return this.tempDir;
  }

  getCreatedFiles(): string[] {
    return this.createdFiles;
  }

  cleanup(): void {
    if (fs.existsSync(this.tempDir)) {
      fs.rmSync(this.tempDir, { recursive: true, force: true });
    }
  }
}
