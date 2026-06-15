import { LanguageAdapter } from "../language-adapter.interface";
import { RepositoryFileDescriptor, RouteFact, SourceFactSet } from "../../domain/appsec.types";

export class RustAdapter implements LanguageAdapter {
  readonly id = "rust";

  supports(file: RepositoryFileDescriptor): boolean {
    return file.isSource && file.extension === "rs";
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
      // e.g. use std::path::Path; or use rocket::get;
      const useMatch = line.match(/^use\s+([A-Za-z0-9_:]+)/);
      if (useMatch) {
        // extract the crate name (first segment)
        const parts = useMatch[1].split("::");
        if (parts[0] && parts[0] !== "crate" && parts[0] !== "self" && parts[0] !== "super") {
          imports.add(parts[0]);
        }
      }

      // 2. Env References
      // e.g. std::env::var("PORT") or env::var("PORT")
      const envMatches = line.matchAll(/(?:std::)?env::var\(\s*['"]([^'"]+)['"]\s*\)/g);
      for (const match of envMatches) {
        if (match[1]) {
          envReferences.add(`env.var.${match[1]}`);
        }
      }

      // 3. Declarations
      // e.g. pub struct AppConfig {
      const structMatch = line.match(/^(?:pub(?:\([^)]+\))?\s+)?struct\s+([A-Za-z0-9_]+)/);
      if (structMatch) {
        declarations.push({ name: structMatch[1], kind: "class" });
        if (line.startsWith("pub ")) {
          exports.push(structMatch[1]);
        }
      }

      // e.g. pub fn process_data(
      const fnMatch = line.match(/^(?:pub(?:\([^)]+\))?\s+)?fn\s+([A-Za-z0-9_]+)/);
      if (fnMatch) {
        declarations.push({ name: fnMatch[1], kind: "function" });
        if (line.startsWith("pub ")) {
          exports.push(fnMatch[1]);
        }
      }

      // 4. Routes (Rocket/Actix-web Attributes, Axum Routing)
      // e.g. #[get("/users")] or #[post("/login")] or .route("/path", ...)
      const routeAttrMatch = line.match(/^#\[(get|post|put|delete|patch)\(\s*['"]([^'"]+)['"]/i);
      if (routeAttrMatch) {
        const framework = "rust-web";
        const method = routeAttrMatch[1].toUpperCase();
        const routePath = routeAttrMatch[2];
        
        let authenticationHint: RouteFact["authenticationHint"] = "unknown";
        if (content.toLowerCase().includes("auth") || content.toLowerCase().includes("claims") || content.toLowerCase().includes("jwt")) {
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

      // Axum: .route("/api/users", post(handler))
      const axumRouteMatch = line.match(/\.route\(\s*['"]([^'"]+)['"]\s*,\s*(get|post|put|delete|patch|options)\(/i);
      if (axumRouteMatch) {
        routes.push({
          framework: "rust-axum",
          method: axumRouteMatch[2].toUpperCase(),
          path: axumRouteMatch[1],
          middleware: [],
          authenticationHint: "unknown",
        });
      }

      // 5. Function Calls
      const callMatches = line.matchAll(/([A-Za-z0-9_]+::[A-Za-z0-9_:]+)\(/g);
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
