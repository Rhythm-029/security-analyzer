import { LanguageAdapter } from "../language-adapter.interface";
import { RepositoryFileDescriptor, RouteFact, SourceFactSet } from "../../domain/appsec.types";

export class GoAdapter implements LanguageAdapter {
  readonly id = "go";

  supports(file: RepositoryFileDescriptor): boolean {
    return file.isSource && file.extension === "go";
  }

  async parse(file: RepositoryFileDescriptor, content: string): Promise<SourceFactSet> {
    const lines = content.split(/\r?\n/);
    const imports = new Set<string>();
    const functionCalls = new Set<string>();
    const envReferences = new Set<string>();
    const routes: RouteFact[] = [];
    const declarations: SourceFactSet["declarations"] = [];
    const exports: string[] = [];

    let inImportBlock = false;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith("//") || line.startsWith("/*")) {
        continue;
      }

      // 1. Imports
      if (line.startsWith("import (") || line === "import(") {
        inImportBlock = true;
        continue;
      }
      if (inImportBlock && line === ")") {
        inImportBlock = false;
        continue;
      }

      if (inImportBlock) {
        const match = line.match(/(?:[A-Za-z0-9_]+\s+)?["']([^"']+)["']/);
        if (match) {
          imports.add(match[1]);
        }
      } else {
        const match = line.match(/^import\s+(?:[A-Za-z0-9_]+\s+)?["']([^"']+)["']/);
        if (match) {
          imports.add(match[1]);
        }
      }

      // 2. Env References
      // e.g. os.Getenv("PORT"), os.LookupEnv("DB_HOST")
      const envMatches = line.matchAll(/os\.(?:Getenv|LookupEnv)\(\s*['"]([^'"]+)['"]\s*\)/g);
      for (const match of envMatches) {
        if (match[1]) {
          envReferences.add(`os.Getenv.${match[1]}`);
        }
      }

      // 3. Declarations
      // e.g., func MyFunction(
      const funcMatch = line.match(/^func\s+([A-Za-z0-9_]+)\s*\(/);
      if (funcMatch) {
        declarations.push({ name: funcMatch[1], kind: "function" });
        // In Go, upper case first character means exported
        if (/^[A-Z]/.test(funcMatch[1])) {
          exports.push(funcMatch[1]);
        }
      }

      // e.g., type Config struct
      const structMatch = line.match(/^type\s+([A-Za-z0-9_]+)\s+struct/);
      if (structMatch) {
        declarations.push({ name: structMatch[1], kind: "class" });
        if (/^[A-Z]/.test(structMatch[1])) {
          exports.push(structMatch[1]);
        }
      }

      // 4. Routes
      // e.g., r.GET("/users", handler) or router.POST("/login", handler)
      const routeMatch = line.match(/(?:r|router|route|engine|group)\.(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\(\s*['"]([^'"]+)['"]/i);
      if (routeMatch) {
        const framework = "go-web";
        const method = routeMatch[1].toUpperCase();
        const routePath = routeMatch[2];
        
        let authenticationHint: RouteFact["authenticationHint"] = "unknown";
        if (line.includes("auth") || line.includes("Auth") || line.includes("jwt") || line.includes("JWT")) {
          authenticationHint = "required";
        }

        routes.push({
          framework,
          method,
          path: routePath,
          middleware: [],
          authenticationHint,
        });
      }

      // 5. Function Calls
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
