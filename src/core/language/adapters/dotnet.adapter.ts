import { LanguageAdapter } from "../language-adapter.interface";
import { RepositoryFileDescriptor, RouteFact, SourceFactSet } from "../../domain/appsec.types";

export class DotnetAdapter implements LanguageAdapter {
  readonly id = "dotnet";

  supports(file: RepositoryFileDescriptor): boolean {
    return file.isSource && (file.extension === "cs" || file.extension === "fs");
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

      // 1. Imports (using directives)
      // e.g. using System.Text;
      const usingMatch = line.match(/^using\s+([A-Za-z0-9_.]+);/);
      if (usingMatch) {
        imports.add(usingMatch[1]);
      }

      // 2. Env References
      // e.g. Environment.GetEnvironmentVariable("PORT")
      const envMatches = line.matchAll(/Environment\.GetEnvironmentVariable\(\s*['"]([^'"]+)['"]\s*\)/g);
      for (const match of envMatches) {
        if (match[1]) {
          envReferences.add(`Environment.getenv.${match[1]}`);
        }
      }

      // 3. Declarations
      // e.g. public class UserController
      const classMatch = line.match(/^(?:public\s+|private\s+|protected\s+|internal\s+)?class\s+([A-Za-z0-9_]+)/);
      if (classMatch) {
        declarations.push({ name: classMatch[1], kind: "class" });
        exports.push(classMatch[1]);
      }

      // e.g. public interface IUserService
      const interfaceMatch = line.match(/^(?:public\s+)?interface\s+([A-Za-z0-9_]+)/);
      if (interfaceMatch) {
        declarations.push({ name: interfaceMatch[1], kind: "interface" });
        exports.push(interfaceMatch[1]);
      }

      // 4. Routes (ASP.NET MVC Annotations)
      // e.g. [HttpGet("/api/users")], [HttpPost("login")], [Route("api/[controller]")]
      const routeMatch = line.match(/^\[(HttpGet|HttpPost|HttpPut|HttpDelete|Route)\(\s*['"]([^'"]+)['"]/i);
      if (routeMatch) {
        const framework = "aspnet-core";
        const mapType = routeMatch[1].toUpperCase();
        const routePath = routeMatch[2];
        
        let method = "GET";
        if (mapType.includes("POST")) method = "POST";
        else if (mapType.includes("PUT")) method = "PUT";
        else if (mapType.includes("DELETE")) method = "DELETE";

        let authenticationHint: RouteFact["authenticationHint"] = "unknown";
        if (content.toLowerCase().includes("[authorize]") || content.toLowerCase().includes("user.identity")) {
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
