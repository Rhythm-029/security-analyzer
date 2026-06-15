import { LanguageAdapter } from "../language-adapter.interface";
import { RepositoryFileDescriptor, RouteFact, SourceFactSet } from "../../domain/appsec.types";

export class JavaAdapter implements LanguageAdapter {
  readonly id = "java";

  supports(file: RepositoryFileDescriptor): boolean {
    return file.isSource && file.extension === "java";
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
      if (!line || line.startsWith("//") || line.startsWith("/*") || line.startsWith("*")) {
        continue;
      }

      // 1. Imports
      // e.g. import java.util.List;
      const importMatch = line.match(/^import\s+([A-Za-z0-9_.]+);/);
      if (importMatch) {
        imports.add(importMatch[1]);
      }

      // 2. Env References
      // e.g. System.getenv("PORT") or System.getProperty("DB_HOST")
      const envMatches = line.matchAll(/System\.(?:getenv|getProperty)\(\s*['"]([^'"]+)['"]\s*\)/g);
      for (const match of envMatches) {
        if (match[1]) {
          envReferences.add(`System.getenv.${match[1]}`);
        }
      }

      // 3. Declarations
      // e.g. public class MyController {
      const classMatch = line.match(/^(?:public\s+|private\s+|protected\s+)?(?:abstract\s+)?class\s+([A-Za-z0-9_]+)/);
      if (classMatch) {
        declarations.push({ name: classMatch[1], kind: "class" });
        exports.push(classMatch[1]);
      }

      // e.g. public interface MyRepository {
      const interfaceMatch = line.match(/^(?:public\s+)?interface\s+([A-Za-z0-9_]+)/);
      if (interfaceMatch) {
        declarations.push({ name: interfaceMatch[1], kind: "interface" });
        exports.push(interfaceMatch[1]);
      }

      // 4. Routes (Spring Boot Annotations)
      // e.g. @GetMapping("/api/users"), @PostMapping(value = "/login")
      const routeMatch = line.match(/^@(GetMapping|PostMapping|PutMapping|DeleteMapping|RequestMapping)\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]/i);
      if (routeMatch) {
        const framework = "spring-boot";
        const mapType = routeMatch[1].toUpperCase();
        const routePath = routeMatch[2];
        
        let method = "GET";
        if (mapType.includes("POST")) method = "POST";
        else if (mapType.includes("PUT")) method = "PUT";
        else if (mapType.includes("DELETE")) method = "DELETE";

        let authenticationHint: RouteFact["authenticationHint"] = "unknown";
        // Check if there is @PreAuthorize or similar auth annotation nearby
        const classOrMethodContext = content.toLowerCase();
        if (classOrMethodContext.includes("securitycontext") || classOrMethodContext.includes("preauthorize") || classOrMethodContext.includes("secured")) {
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
