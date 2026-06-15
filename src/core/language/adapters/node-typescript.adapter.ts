import {
  CallExpression,
  ClassDeclaration,
  FunctionDeclaration,
  InterfaceDeclaration,
  Project,
  PropertyAccessExpression,
  SyntaxKind,
} from "ts-morph";
import { LanguageAdapter } from "../language-adapter.interface";
import { RepositoryFileDescriptor, RouteFact, SourceFactSet } from "../../domain/appsec.types";

const SUPPORTED_EXTENSIONS = new Set(["ts", "tsx", "js", "jsx", "mjs", "cjs"]);

export class NodeTypescriptAdapter implements LanguageAdapter {
  readonly id = "node-typescript";

  private readonly project = new Project({
    compilerOptions: {
      allowJs: true,
      noResolve: true,
    },
  });

  supports(file: RepositoryFileDescriptor): boolean {
    return file.isSource && SUPPORTED_EXTENSIONS.has(file.extension);
  }

  async parse(file: RepositoryFileDescriptor, content: string): Promise<SourceFactSet> {
    const sourceFile = this.project.createSourceFile(file.absolutePath, content, { overwrite: true });

    const imports = new Set<string>();
    sourceFile.getImportDeclarations().forEach(importDeclaration => {
      imports.add(importDeclaration.getModuleSpecifierValue());
    });

    sourceFile.getExportDeclarations().forEach(exportDeclaration => {
      const specifier = exportDeclaration.getModuleSpecifierValue();
      if (specifier) {
        imports.add(specifier);
      }
    });

    const functionCalls = new Set<string>();
    const routes: RouteFact[] = [];
    sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression).forEach((callExpression: CallExpression) => {
      const expressionNode = callExpression.getExpression();
      const expression = expressionNode.getText();
      functionCalls.add(expression);

      // Handle CommonJS require(...)
      if (expression === "require") {
        const args = callExpression.getArguments();
        if (args.length === 1) {
          const argText = args[0].getText().replace(/^['"`]|['"`]$/g, "");
          if (argText) {
            imports.add(argText);
          }
        }
      }

      // Handle dynamic import(...)
      if (expression === "import" || expressionNode.getKind() === SyntaxKind.ImportKeyword) {
        const args = callExpression.getArguments();
        if (args.length === 1) {
          const argText = args[0].getText().replace(/^['"`]|['"`]$/g, "");
          if (argText) {
            imports.add(argText);
          }
        }
      }

      const routeFact = this.tryParseRouteFact(expression, callExpression);
      if (routeFact) {
        routes.push(routeFact);
      }
    });

    // Handle Vercel / Next.js / Serverless API directory routing
    const relPath = file.relativePath.replace(/\\/g, "/");
    const apiIndex = relPath.indexOf("api/");
    if (apiIndex !== -1) {
      const apiSubpath = relPath.substring(apiIndex);
      const routePart = "/" + apiSubpath.replace(/\.[a-zA-Z0-9]+$/, "");
      const normalizedRoutePath = routePart
        .replace(/\[\.\.\.[a-zA-Z0-9_-]+\]/g, "*")
        .replace(/\[([a-zA-Z0-9_-]+)\]/g, ":$1");

      const methods: string[] = [];
      const contentLower = content.toLowerCase();
      if (contentLower.includes("req.method === 'post'") || contentLower.includes('req.method === "post"') || contentLower.includes("method === 'post'") || contentLower.includes('method === "post"')) {
        methods.push("POST");
      }
      if (contentLower.includes("req.method === 'get'") || contentLower.includes('req.method === "get"') || contentLower.includes("method === 'get'") || contentLower.includes('method === "get"')) {
        methods.push("GET");
      }
      if (contentLower.includes("req.method === 'put'") || contentLower.includes('req.method === "put"') || contentLower.includes("method === 'put'") || contentLower.includes('method === "put"')) {
        methods.push("PUT");
      }
      if (contentLower.includes("req.method === 'delete'") || contentLower.includes('req.method === "delete"') || contentLower.includes("method === 'delete'") || contentLower.includes('method === "delete"')) {
        methods.push("DELETE");
      }

      if (methods.length === 0) {
        methods.push("GET", "POST");
      }

      const authKeywords = ["authenticate", "passport", "auth", "token", "jwt", "verifytoken", "session"];
      const hasAuth = authKeywords.some(keyword => contentLower.includes(keyword));
      const authenticationHint = hasAuth ? "required" : "unknown";

      const pathRegex = /(?:path|url)\s*===?\s*['"](\/[a-zA-Z0-9_/.-]+)['"]/gi;
      const subroutes = new Set<string>();
      let pathMatch;
      while ((pathMatch = pathRegex.exec(content)) !== null) {
        subroutes.add(pathMatch[1]);
      }

      const baseRoutePath = normalizedRoutePath.endsWith("/*")
        ? normalizedRoutePath.slice(0, -2)
        : normalizedRoutePath;

      if (subroutes.size > 0) {
        subroutes.forEach(subpath => {
          const fullPath = `${baseRoutePath.replace(/\/$/, "")}/${subpath.replace(/^\//, "")}`;
          methods.forEach(method => {
            routes.push({
              framework: "vercel",
              method,
              path: fullPath,
              middleware: [],
              authenticationHint,
            });
          });
        });
      } else {
        methods.forEach(method => {
          routes.push({
            framework: "vercel",
            method,
            path: normalizedRoutePath,
            middleware: [],
            authenticationHint,
          });
        });
      }
    }

    const envReferences = new Set<string>();
    sourceFile.getDescendantsOfKind(SyntaxKind.PropertyAccessExpression).forEach((expression: PropertyAccessExpression) => {
      const text = expression.getText();
      if (text.startsWith("process.env.")) {
        envReferences.add(text);
      }
    });

    const declarations = [
      ...sourceFile.getDescendantsOfKind(SyntaxKind.ClassDeclaration).flatMap((node: ClassDeclaration) => {
        const name = node.getName();
        return name ? [{ name, kind: "class" as const }] : [];
      }),
      ...sourceFile.getDescendantsOfKind(SyntaxKind.FunctionDeclaration).flatMap((node: FunctionDeclaration) => {
        const name = node.getName();
        return name ? [{ name, kind: "function" as const }] : [];
      }),
      ...sourceFile.getDescendantsOfKind(SyntaxKind.InterfaceDeclaration).flatMap((node: InterfaceDeclaration) => {
        const name = node.getName();
        return name ? [{ name, kind: "interface" as const }] : [];
      }),
    ];

    const exports = Array.from(sourceFile.getExportedDeclarations().keys());

    return {
      imports: Array.from(imports),
      functionCalls: Array.from(functionCalls),
      envReferences: Array.from(envReferences),
      routes,
      declarations,
      exports,
    };
  }

  private tryParseRouteFact(expression: string, callExpression: CallExpression): RouteFact | undefined {
    const routeMatch = expression.match(/^(router|app|fastify|server)\.(get|post|put|delete|patch|options|head)$/i);
    if (!routeMatch) {
      return undefined;
    }

    const method = routeMatch[2].toUpperCase();
    const args = callExpression.getArguments();
    const routePath = args[0]?.getText().replace(/^['"]|['"]$/g, "") || "";
    const middleware = args.slice(1).map(argument => argument.getText());
    const authenticationIndicators = [

  "authenticate",
  "passport.authenticate",

  "requireauth",

  "ensureauthenticated",

  "jwtmiddleware",

  "verifytoken",

];

const authenticationHint =
  middleware.some(
    argument => {

      const lower =
        argument.toLowerCase();

      return authenticationIndicators.some(
        indicator =>
          lower.includes(indicator)
      );

    }
  )
    ? "required"
    : "unknown";

    return {
      framework: routeMatch[1].toLowerCase(),
      method,
      path: routePath,
      middleware,
      authenticationHint,
    };
  }
}
