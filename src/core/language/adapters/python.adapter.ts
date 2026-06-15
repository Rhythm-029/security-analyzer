import { LanguageAdapter } from "../language-adapter.interface";
import { RepositoryFileDescriptor, RouteFact, SourceFactSet } from "../../domain/appsec.types";

export class PythonAdapter implements LanguageAdapter {
  readonly id = "python";

  supports(file: RepositoryFileDescriptor): boolean {
    return file.isSource && file.extension === "py";
  }

  async parse(file: RepositoryFileDescriptor, content: string): Promise<SourceFactSet> {
    const lines = content.split(/\r?\n/);
    const imports = new Set<string>();
    const functionCalls = new Set<string>();
    const envReferences = new Set<string>();
    const routes: RouteFact[] = [];
    const declarations: SourceFactSet["declarations"] = [];
    const exports: string[] = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("#")) {
        continue;
      }

      // 1. Imports
      // e.g., "import os", "import package.module as name"
      const importMatch = line.match(/^import\s+([A-Za-z0-9_.,\s]+)/);
      if (importMatch) {
        importMatch[1].split(",").forEach(item => {
          const name = item.trim().split(/\s+as\s+/)[0].trim();
          imports.add(name);
        });
      }

      // e.g., "from package.module import something"
      const fromImportMatch = line.match(/^from\s+([A-Za-z0-9_.]+)\s+import\s+/);
      if (fromImportMatch) {
        imports.add(fromImportMatch[1]);
      }

      // 2. Env References
      // e.g., "os.environ.get('PORT')", "os.getenv('PORT')", "os.environ['PORT']"
      const envMatches = line.matchAll(/os\.(?:environ\.get|getenv)\(\s*['"]([^'"]+)['"]\s*\)|os\.environ\[\s*['"]([^'"]+)['"]\s*\]/g);
      for (const match of envMatches) {
        const envVar = match[1] || match[2];
        if (envVar) {
          envReferences.add(`os.environ.${envVar}`);
        }
      }

      // 3. Declarations
      // e.g., "class ClassName:", "class ClassName(Base):"
      const classMatch = line.match(/^class\s+([A-Za-z0-9_]+)/);
      if (classMatch) {
        declarations.push({ name: classMatch[1], kind: "class" });
        exports.push(classMatch[1]);
      }

      // e.g., "def func_name("
      const funcMatch = line.match(/^def\s+([A-Za-z0-9_]+)\s*\(/);
      if (funcMatch) {
        declarations.push({ name: funcMatch[1], kind: "function" });
        exports.push(funcMatch[1]);
      }

      // 4. Routes
      // e.g., @app.get('/users') or @router.post('/login')
      const routeMatch = line.match(/^@(app|router|blueprint)\.(get|post|put|delete|patch|route)\(\s*['"]([^'"]+)['"]/i);
      if (routeMatch) {
        const framework = "python-web";
        const method = routeMatch[2].toUpperCase();
        const routePath = routeMatch[3];
        
        // Check authentication hint in middleware or adjacent line
        let authenticationHint: RouteFact["authenticationHint"] = "unknown";
        if (content.toLowerCase().includes("login_required") || line.includes("auth")) {
          authenticationHint = "required";
        }

        routes.push({
          framework,
          method: method === "ROUTE" ? "GET" : method,
          path: routePath,
          middleware: [],
          authenticationHint,
        });
      }

      // 5. Function Calls (evidence-based)
      // e.g. jwt.encode(...), bcrypt.hashpw(...)
      const callMatches = line.matchAll(/([A-Za-z0-9_]+\.[A-Za-z0-9_.]+)\(/g);
      for (const match of callMatches) {
        functionCalls.add(match[1]);
      }
    }

    return {
      imports: Array.from(imports),
      functionCalls: Array.from(functionCalls),
      envReferences: Array.from(envReferences),
      routes,
      declarations,
      exports,
    };
  }
}
