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

    const functionCalls = new Set<string>();
    const routes: RouteFact[] = [];
    sourceFile.getDescendantsOfKind(SyntaxKind.CallExpression).forEach((callExpression: CallExpression) => {
      const expression = callExpression.getExpression().getText();
      functionCalls.add(expression);

      const routeFact = this.tryParseRouteFact(expression, callExpression);
      if (routeFact) {
        routes.push(routeFact);
      }
    });

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
