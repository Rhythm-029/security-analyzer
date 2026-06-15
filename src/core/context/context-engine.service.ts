import path from "path";
import {
  AnalysisReport,
  CapabilityDescriptor,
  DataStoreDescriptor,
  DependencyAnalysisResult,
  DependencyDescriptor,
  DependencyManifestFact,
  ExposureDescriptor,
  ModuleDescriptor,
  RepositoryContext,
  RepositoryCoverage,
  RepositoryFileDescriptor,
  RepositoryGraphSnapshot,
  ScanOptions,
  SourceFactSet,
  TechnologyDescriptor,
} from "../domain/appsec.types";
import { mapWithConcurrency } from "../utils/async";
import { RepositoryScannerService } from "../scanner/repository-scanner.service";
import { LanguageRegistryService } from "../language/language-registry.service";
import { NodeTypescriptAdapter } from "../language/adapters/node-typescript.adapter";
import { RepositoryGraphService } from "../graph/repository-graph.service";
import { DependencyAnalyzerService } from "../dependency/dependency-analyzer.service";
import { CapabilityAnalyzerService } from "../capability/capability-analyzer.service";
import { ContextEngineContract } from "../contracts/appsec.contracts";
import { PythonAdapter } from "../language/adapters/python.adapter";
import { GoAdapter } from "../language/adapters/go.adapter";
import { JavaAdapter } from "../language/adapters/java.adapter";
import { DotnetAdapter } from "../language/adapters/dotnet.adapter";
import { RustAdapter } from "../language/adapters/rust.adapter";

type FileAnalysisState = {
  file: RepositoryFileDescriptor;
  content?: string;
  facts?: SourceFactSet;
};

const DEFAULT_CONCURRENCY = Math.max(2, Math.min(8, require("os").cpus().length));

export class ContextEngineService implements ContextEngineContract {
  private readonly scanner = new RepositoryScannerService();
  private readonly languageRegistry = new LanguageRegistryService();
  private readonly graph = new RepositoryGraphService();
  private readonly dependencyAnalyzer = new DependencyAnalyzerService();
  private readonly capabilityAnalyzer = new CapabilityAnalyzerService();

  constructor() {
    this.languageRegistry.register(new NodeTypescriptAdapter());
    this.languageRegistry.register(new PythonAdapter());
    this.languageRegistry.register(new GoAdapter());
    this.languageRegistry.register(new JavaAdapter());
    this.languageRegistry.register(new DotnetAdapter());
    this.languageRegistry.register(new RustAdapter());
  }

  async analyze(repositoryPath: string, options?: ScanOptions): Promise<{
    files: RepositoryFileDescriptor[];
    coverage: RepositoryCoverage;
    context: RepositoryContext;
    graph: RepositoryGraphSnapshot;
    sourceFactsByFile: Map<string, SourceFactSet>;
    dependencyAnalysis: DependencyAnalysisResult;
  }> {
    const files = await this.scanner.scan(repositoryPath, options);
    const sourceFactsByFile = new Map<string, SourceFactSet>();
    const fileContents = new Map<string, string>();
    const rootNodeId = this.graph.addRepository(repositoryPath);
    void rootNodeId;

    const analyzableFiles = files.filter(file => file.isSource || file.isManifest || file.isConfiguration);
    const fileStates = await mapWithConcurrency(analyzableFiles, options?.maxConcurrency ?? DEFAULT_CONCURRENCY, async file => {
      const state: FileAnalysisState = { file };
      state.content = await this.scanner.readText(file.absolutePath);
      fileContents.set(file.absolutePath, state.content);
      this.graph.addFile(file);

      if (file.isManifest) {
        this.graph.addManifest(file);
      }

      if (file.isSource) {
        const adapter = this.languageRegistry.resolve(file);
        if (adapter) {
          try {
            state.facts = await adapter.parse(file, state.content);
            sourceFactsByFile.set(file.absolutePath, state.facts);
          } catch (e) {
            console.error(`Error parsing source file ${file.absolutePath} with adapter ${adapter.id}:`, e);
          }
        }
      }

      return state;
    });

    for (const state of fileStates) {
      if (!state.facts) {
        continue;
      }

      this.ingestSourceFacts(state.file, state.facts, files);
    }

    const dependencyAnalysis = await this.dependencyAnalyzer.analyze(files, fileContents, sourceFactsByFile);
    const context = this.buildRepositoryContext(files, sourceFactsByFile, dependencyAnalysis);
    const coverage = this.buildCoverage(files, sourceFactsByFile, fileContents, dependencyAnalysis);

    return {
      files,
      coverage,
      context,
      graph: this.graph.snapshot(),
      sourceFactsByFile,
      dependencyAnalysis,
    };
  }

  private ingestSourceFacts(file: RepositoryFileDescriptor, facts: SourceFactSet, files: RepositoryFileDescriptor[]): void {
    const fileNodeId = `file:${file.absolutePath}`;
    const fileDir = path.posix.normalize(path.posix.dirname(file.relativePath));

    this.graph.addModule(this.deriveModuleName(file, files), file.absolutePath, {
      boundary: fileDir,
      fileCount: 1,
    });

    for (const importSpecifier of facts.imports) {
      if (this.isLocalImport(importSpecifier)) {
        const resolved = this.resolveLocalImport(file, importSpecifier, files);
        if (resolved) {
          this.graph.addEdge({
            from: fileNodeId,
            to: `file:${resolved.absolutePath}`,
            kind: "imports",
            metadata: {
              specifier: importSpecifier,
              relation: "local",
            },
          });
        } else {
          this.graph.addEdge({
            from: fileNodeId,
            to: `module:${importSpecifier}`,
            kind: "imports",
            metadata: {
              specifier: importSpecifier,
              relation: "unresolved-local",
            },
          });
        }
      } else {
        this.graph.addEdge({
          from: fileNodeId,
          to: `dependency:${this.normalizePackageName(importSpecifier) ?? importSpecifier}`,
          kind: "imports",
          metadata: {
            specifier: importSpecifier,
            relation: "external",
          },
        });
      }
    }

    for (const declaration of facts.declarations) {
      this.graph.addEdge({
        from: fileNodeId,
        to: `symbol:${declaration.kind}:${declaration.name}`,
        kind: "declares",
        metadata: {
          declarationKind: declaration.kind,
        },
      });
    }

    for (const callExpression of facts.functionCalls) {
      this.graph.addEdge({
        from: fileNodeId,
        to: `symbol:call:${callExpression}`,
        kind: "calls",
        metadata: {
          callExpression,
        },
      });
    }

    for (const envReference of facts.envReferences) {
      this.graph.addEdge({
        from: fileNodeId,
        to: `symbol:env:${envReference}`,
        kind: "references",
        metadata: {
          reference: envReference,
        },
      });
    }
  }

  private buildRepositoryContext(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    dependencyAnalysis: DependencyAnalysisResult,
  ): RepositoryContext {
    const technologyStack = this.deriveTechnologies(files, sourceFactsByFile, dependencyAnalysis);
    const repositoryModules = this.deriveModules(files, sourceFactsByFile, dependencyAnalysis);
    const securityModules = this.deriveSecurityModules(files, sourceFactsByFile, dependencyAnalysis);
    const thirdPartyServices = this.deriveServices(files, sourceFactsByFile, dependencyAnalysis);
    const dataStores = this.deriveDataStores(files, sourceFactsByFile, dependencyAnalysis);
    const exposures = this.deriveExposures(files, sourceFactsByFile, dependencyAnalysis);
    const capabilities = this.capabilityAnalyzer.analyze({
      graph: this.graph.snapshot(),
      sourceFactsByFile,
      dependencyFacts: dependencyAnalysis,
    });

    const technologyById = new Map<string, TechnologyDescriptor>();
    technologyStack.forEach(technology => technologyById.set(technology.id, technology));

    const dependencySummary = dependencyAnalysis.dependencies;

    return {
      technologyStack: Array.from(technologyById.values()),
      thirdPartyDependencies: dependencySummary,
      thirdPartyServices,
      repositoryModules,
      securityModules,
      capabilities,
      exposures,
      dataStores,
    };
  }

  private buildCoverage(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    fileContents: Map<string, string>,
    dependencyAnalysis: DependencyAnalysisResult,
  ): RepositoryCoverage {
    const manifestFiles = files.filter(file => file.isManifest).length;
    const configurationFiles = files.filter(file => file.isConfiguration).length;
    const binaryFiles = files.filter(file => file.isBinary).length;
    const sourceFiles = files.filter(file => file.isSource).length;
    const parsedFiles = sourceFactsByFile.size + dependencyAnalysis.manifests.length;
    const unsupportedFiles = files.length - parsedFiles - binaryFiles;

    void fileContents;

    return {
      parsedFiles,
      sourceFiles,
      manifestFiles,
      configurationFiles,
      unsupportedFiles: Math.max(0, unsupportedFiles),
      binaryFiles,
    };
  }

  private mapDirectoryToModule(relativePath: string): string {
    const normalized = relativePath.replace(/\\/g, "/");
    
    if (normalized.includes("core/scanner") || normalized.includes("core\\scanner")) return "Scanner Engine";
    if (normalized.includes("core/context") || normalized.includes("core\\context")) return "Context Engine";
    if (normalized.includes("core/risk") || normalized.includes("core\\risk")) return "Risk Engine";
    if (normalized.includes("core/graph") || normalized.includes("core\\graph")) return "Graph Engine";
    if (normalized.includes("core/report") || normalized.includes("core\\report")) return "Report Engine";
    if (normalized.includes("language/adapters") || normalized.includes("language\\adapters")) return "Language Adapters";
    if (normalized.includes("semgrep/")) return "Semgrep Layer";
    if (normalized.includes("routes/") || normalized.endsWith("app.ts") || normalized.endsWith("server.ts") || normalized.endsWith("index.js") || normalized.includes("api/")) return "API Layer";

    // Generic fallback based on parent directory
    const segments = normalized.split("/");
    if (segments.length > 1) {
      const parentDir = segments[segments.length - 2];
      if (parentDir && parentDir !== "src" && parentDir !== "core") {
        return parentDir.replace(/[-_]/g, " ").replace(/\b\w/g, c => c.toUpperCase()) + " Module";
      }
    }
    return "Core Engine";
  }

  private deriveTechnologies(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    dependencyAnalysis: DependencyAnalysisResult,
  ): TechnologyDescriptor[] {
    const technologies = new Map<string, TechnologyDescriptor>();
    
    const addTech = (id: string, name: string, framework: string | undefined, confidence: number, evidence: string[]) => {
      const existing = technologies.get(id);
      if (existing) {
        existing.evidence = Array.from(new Set([...existing.evidence, ...evidence]));
        existing.confidence = Math.max(existing.confidence, confidence);
        if (framework) existing.framework = framework;
      } else {
        technologies.set(id, {
          id,
          name,
          ecosystem: name.toLowerCase(),
          confidence,
          evidence,
          files: [],
          framework,
        });
      }
    };

    const pyFiles = files.filter(f => f.extension === "py").length;
    const goFiles = files.filter(f => f.extension === "go").length;
    const javaFiles = files.filter(f => f.extension === "java" || f.extension === "jar").length;
    const csFiles = files.filter(f => f.extension === "cs").length;
    const rsFiles = files.filter(f => f.extension === "rs").length;
    const jsTsFiles = files.filter(f => ["js", "jsx", "ts", "tsx", "mjs", "cjs"].includes(f.extension)).length;

    const allImports = new Set<string>();
    for (const facts of sourceFactsByFile.values()) {
      facts.imports.forEach(i => allImports.add(i.toLowerCase()));
    }
    const allDeps = new Set<string>();
    dependencyAnalysis.dependencies.forEach(d => allDeps.add(d.name.toLowerCase()));

    // 1. Node.js / JS Ecosystem
    if (jsTsFiles > 0 || allDeps.has("express") || allImports.has("express")) {
      let fw = "Vanilla JS/TS";
      if (allDeps.has("express") || allImports.has("express")) fw = "Express";
      else if (allDeps.has("@nestjs/core") || allDeps.has("nestjs")) fw = "NestJS";
      else if (allDeps.has("fastify") || allImports.has("fastify")) fw = "Fastify";
      else if (allDeps.has("next")) fw = "Next.js";
      
      if (allDeps.has("expo") || allDeps.has("expo-router")) fw = "Expo (React Native)";
      else if (allDeps.has("react-native") || allImports.has("react-native")) fw = "React Native";
      else if (allDeps.has("react") || allImports.has("react")) fw = "React";

      addTech("tech:nodejs", "Node.js", fw, 1.0, ["Found JavaScript/TypeScript files"]);
    }

    // 2. Python Ecosystem
    if (pyFiles > 0 || allDeps.has("django") || allDeps.has("fastapi") || allDeps.has("flask")) {
      let fw = "Core Python";
      if (allDeps.has("fastapi") || allImports.has("fastapi")) fw = "FastAPI";
      else if (allDeps.has("django") || allImports.has("django")) fw = "Django";
      else if (allDeps.has("flask") || allImports.has("flask")) fw = "Flask";

      addTech("tech:python", "Python", fw, 1.0, ["Found Python files"]);
    }

    // 3. Go Ecosystem
    if (goFiles > 0 || allDeps.has("github.com/gin-gonic/gin") || allImports.has("github.com/gin-gonic/gin")) {
      let fw = "Core Go";
      if (allDeps.has("github.com/gin-gonic/gin") || allImports.has("github.com/gin-gonic/gin")) fw = "Gin";
      else if (allDeps.has("github.com/gofiber/fiber") || allImports.has("github.com/gofiber/fiber")) fw = "Fiber";

      addTech("tech:go", "Go", fw, 1.0, ["Found Go source files"]);
    }

    // 4. Java Ecosystem
    if (javaFiles > 0 || allDeps.has("spring-core") || allDeps.has("spring-boot")) {
      let fw = "Core Java";
      if (allDeps.has("spring-core") || allDeps.has("spring-boot") || allImports.has("org.springframework")) fw = "Spring Boot";
      if (allDeps.has("hibernate") || allImports.has("org.hibernate")) fw = fw === "Core Java" ? "Hibernate" : `${fw} + Hibernate`;

      addTech("tech:java", "Java", fw, 1.0, ["Found Java files"]);
    }

    // 5. .NET Ecosystem
    if (csFiles > 0 || allDeps.has("microsoft.aspnetcore") || allDeps.has("microsoft.entityframeworkcore")) {
      let fw = "Core .NET";
      if (allDeps.has("microsoft.aspnetcore") || allImports.has("microsoft.aspnetcore")) fw = "ASP.NET Core";
      if (allDeps.has("microsoft.entityframeworkcore") || allImports.has("microsoft.entityframeworkcore")) fw = fw === "Core .NET" ? "Entity Framework" : `${fw} + Entity Framework`;

      addTech("tech:dotnet", ".NET", fw, 1.0, ["Found C# source files"]);
    }

    // 6. Rust Ecosystem
    if (rsFiles > 0 || allDeps.has("actix-web") || allDeps.has("rocket")) {
      let fw = "Core Rust";
      if (allDeps.has("actix-web") || allImports.has("actix-web") || allImports.has("actix")) fw = "Actix-Web";
      else if (allDeps.has("rocket") || allImports.has("rocket")) fw = "Rocket";

      addTech("tech:rust", "Rust", fw, 1.0, ["Found Rust source files"]);
    }

    return Array.from(technologies.values());
  }

  private deriveModules(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    dependencyAnalysis: DependencyAnalysisResult,
  ): ModuleDescriptor[] {
    const modules = new Map<string, ModuleDescriptor>();

    for (const file of files) {
      if (!file.isSource && !file.isManifest) {
        continue;
      }

      const moduleName = this.mapDirectoryToModule(file.relativePath);
      const moduleId = `module:${moduleName.toLowerCase().replace(/\s+/g, "-")}`;
      
      const facts = sourceFactsByFile.get(file.absolutePath);
      const imports = facts?.imports ?? [];
      const exports = facts?.exports ?? [];

      const existing = modules.get(moduleId);
      
      let kind: ModuleDescriptor["kind"] = "module";
      if (moduleName.endsWith("Engine")) kind = "service";
      else if (moduleName.endsWith("Layer")) kind = "boundary";
      else if (moduleName.endsWith("Adapters")) kind = "library";

      if (!existing) {
        modules.set(moduleId, {
          id: moduleId,
          name: moduleName,
          kind,
          files: [file.absolutePath],
          imports: Array.from(imports),
          exports: Array.from(exports),
          confidence: 0.9,
          evidence: [file.relativePath],
        });
      } else {
        existing.files.push(file.absolutePath);
        existing.imports = Array.from(new Set([...existing.imports, ...imports]));
        existing.exports = Array.from(new Set([...existing.exports, ...exports]));
        existing.evidence.push(file.relativePath);
      }
    }

    return Array.from(modules.values());
  }

  private deriveSecurityModules(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    dependencyAnalysis: DependencyAnalysisResult,
  ) {
    const securityModules = new Map<string, {
      id: string;
      name: string;
      category:
        | "authentication"
        | "authorization"
        | "crypto"
        | "secret_management"
        | "input_validation"
        | "access_control"
        | "session_management"
        | "policy"
        | "other";
      files: string[];
      evidence: string[];
      confidence: number;
    }>();

    const add = (
      name: string,
      category:
        | "authentication"
        | "authorization"
        | "crypto"
        | "secret_management"
        | "input_validation"
        | "access_control"
        | "session_management"
        | "policy"
        | "other",
      filePath: string,
      evidence: string[],
      confidence: number
    ) => {
      const id = `security:${name}`;
      const existing = securityModules.get(id);

      if (!existing) {
        securityModules.set(id, {
          id,
          name,
          category,
          files: [filePath],
          evidence,
          confidence
        });
        return;
      }

      existing.files = Array.from(new Set([...existing.files, filePath]));
      existing.evidence = Array.from(new Set([...existing.evidence, ...evidence]));
      existing.confidence = Math.max(existing.confidence, confidence);
    };

    const authenticationIndicators = [
      "jwt.sign",
      "jwt.verify",
      "passport.authenticate",
      "passport.use",
      "oauth.authenticate",
      "securitycontextholder",
      "authenticationmanager"
    ];

    const authorizationIndicators = [
      "authorize",
      "checkpermission",
      "hasrole",
      "hasauthority",
      "rbac",
      "acl"
    ];

    const cryptoIndicators = [
      "bcrypt.hash",
      "bcrypt.compare",
      "crypto.createhash",
      "crypto.encrypt",
      "crypto.decrypt",
      "openssl"
    ];

    for (const [filePath, facts] of sourceFactsByFile.entries()) {
      const lowerCalls = facts.functionCalls.map(call => call.toLowerCase());

      if (
        lowerCalls.some(
          call =>
            authenticationIndicators.some(
              indicator => call.includes(indicator)
            )
        )
      ) {
        add("authentication", "authentication", filePath, facts.functionCalls, 0.95);
      }

      if (
        lowerCalls.some(
          call =>
            authorizationIndicators.some(
              indicator => call.includes(indicator)
            )
        )
      ) {
        add("authorization", "authorization", filePath, facts.functionCalls, 0.9);
      }

      if (
        lowerCalls.some(
          call =>
            cryptoIndicators.some(
              indicator => call.includes(indicator)
            )
        )
      ) {
        add("crypto", "crypto", filePath, facts.functionCalls, 0.95);
      }

      const sensitiveEnvKeywords = ["key", "secret", "token", "password", "pwd", "auth", "cred", "cert", "private", "hash", "salt"];
      const SENSITIVE_EXCLUDE = ["port", "home", "node_env", "repository_path", "host", "path"];

      const sensitiveReferences = facts.envReferences.filter(ref => {
        const lower = ref.toLowerCase();
        const matchesSensitive = sensitiveEnvKeywords.some(keyword => lower.includes(keyword));
        const isExcluded = SENSITIVE_EXCLUDE.some(excl => lower.endsWith("." + excl) || lower.endsWith("['" + excl + "']") || lower.endsWith("[\"" + excl + "\"]"));
        return matchesSensitive && !isExcluded;
      });

      if (sensitiveReferences.length > 0) {
        add("secret_management", "secret_management", filePath, sensitiveReferences, 0.85);
      }
    }

    for (const dependency of dependencyAnalysis.dependencies) {
      const name = dependency.name.toLowerCase();
      if (
        name === "jsonwebtoken" ||
        name === "passport" ||
        name === "passport-jwt"
      ) {
        add("authentication", "authentication", dependency.sourceFile, [dependency.name], 0.85);
      }

      if (name === "bcrypt" || name === "bcryptjs") {
        add("crypto", "crypto", dependency.sourceFile, [dependency.name], 0.85);
      }

      if (name.includes("vault") || name.includes("kms")) {
        add("secret_management", "secret_management", dependency.sourceFile, [dependency.name], 0.9);
      }
    }

    void files;

    return Array.from(securityModules.values());
  }

  private deriveServices(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    dependencyAnalysis: DependencyAnalysisResult,
  ) {
    const services = new Map<string, {
      id: string;
      name: string;
      category: "identity" | "payment" | "storage" | "messaging" | "email" | "analytics" | "logging" | "feature_flag" | "ai" | "unknown";
      endpoints: string[];
      files: string[];
      evidence: string[];
      confidence: number;
    }>();

    const add = (name: string, category: "identity" | "payment" | "storage" | "messaging" | "email" | "analytics" | "logging" | "feature_flag" | "ai" | "unknown", filePath: string, evidence: string[], confidence: number) => {
      const id = `service:${name}`;
      const existing = services.get(id);
      if (!existing) {
        services.set(id, {
          id,
          name,
          category,
          endpoints: [],
          files: [filePath],
          evidence,
          confidence,
        });
        return;
      }

      existing.files = Array.from(new Set([...existing.files, filePath]));
      existing.evidence = Array.from(new Set([...existing.evidence, ...evidence]));
      existing.confidence = Math.max(existing.confidence, confidence);
    };

    for (const dependency of dependencyAnalysis.dependencies) {
      const name = dependency.name.toLowerCase();
      if (name.includes("firebase") || name.includes("auth0") || name.includes("okta") || name.includes("cognito") || name.includes("keycloak")) {
        add("identity", "identity", dependency.sourceFile, [dependency.name], 0.9);
      }
      if (name.includes("stripe") || name.includes("paypal") || name.includes("braintree") || name.includes("square")) {
        add("payment", "payment", dependency.sourceFile, [dependency.name], 0.9);
      }
      if (name.includes("s3") || name.includes("blob") || name.includes("storage") || name.includes("gcs") || name.includes("azure.storage")) {
        add("storage", "storage", dependency.sourceFile, [dependency.name], 0.8);
      }
      if (name.includes("kafka") || name.includes("rabbit") || name.includes("sqs") || name.includes("pubsub") || name.includes("nats")) {
        add("messaging", "messaging", dependency.sourceFile, [dependency.name], 0.85);
      }
      if (name.includes("sendgrid") || name.includes("mail") || name.includes("ses") || name.includes("postmark")) {
        add("email", "email", dependency.sourceFile, [dependency.name], 0.8);
      }
      if (name.includes("datadog") || name.includes("sentry") || name.includes("newrelic") || name.includes("grafana") || name.includes("prometheus")) {
        add("logging", "logging", dependency.sourceFile, [dependency.name], 0.8);
      }
      if (name.includes("launchdarkly") || name.includes("optimizely") || name.includes("feature")) {
        add("feature_flag", "feature_flag", dependency.sourceFile, [dependency.name], 0.7);
      }
      if (name.includes("openai") || name.includes("anthropic") || name.includes("vertexai") || name.includes("bedrock")) {
        add("ai", "ai", dependency.sourceFile, [dependency.name], 0.75);
      }
    }


    return Array.from(services.values());
  }

  private deriveDataStores(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    dependencyAnalysis: DependencyAnalysisResult,
  ) {
    const stores = new Map<string, DataStoreDescriptor>();

    const add = (name: string, kind: DataStoreDescriptor["kind"], filePath: string, evidence: string[], confidence: number) => {
      const id = `datastore:${name}`;
      const existing = stores.get(id);
      if (!existing) {
        stores.set(id, {
          id,
          name,
          kind,
          files: [filePath],
          evidence,
          confidence,
        });
        return;
      }

      existing.files = Array.from(new Set([...existing.files, filePath]));
      existing.evidence = Array.from(new Set([...existing.evidence, ...evidence]));
      existing.confidence = Math.max(existing.confidence, confidence);
    };

    for (const dependency of dependencyAnalysis.dependencies) {
      const name = dependency.name.toLowerCase();
      if (name.includes("postgres") || name.includes("mysql") || name.includes("sqlite") || name.includes("mssql") || name.includes("oracle") || name.includes("jdbc")) {
        add(name, "sql", dependency.sourceFile, [dependency.name], 0.85);
      }
      if (name.includes("mongo") || name.includes("couch") || name.includes("dynamo")) {
        add(name, "nosql", dependency.sourceFile, [dependency.name], 0.8);
      }
      if (name.includes("redis") || name.includes("memcached") || name.includes("cache")) {
        add(name, "cache", dependency.sourceFile, [dependency.name], 0.8);
      }
      if (name.includes("elasticsearch") || name.includes("opensearch") || name.includes("solr")) {
        add(name, "search", dependency.sourceFile, [dependency.name], 0.8);
      }
      if (name.includes("s3") || name.includes("gcs") || name.includes("blob") || name.includes("storage")) {
        add(name, "blob", dependency.sourceFile, [dependency.name], 0.75);
      }
      if (name.includes("queue") || name.includes("kafka") || name.includes("rabbit") || name.includes("sqs") || name.includes("pubsub")) {
        add(name, "queue", dependency.sourceFile, [dependency.name], 0.8);
      }
    }

    for (const [filePath, facts] of sourceFactsByFile.entries()) {
      const lowerCalls = facts.functionCalls.map(call => call.toLowerCase());
      const nosqlIndicators = ["mongoose.connect", "mongoclient.connect"];
      const sqlIndicators = ["prismaclient", "sequelize", "typeorm", "datasource", "drivermanager.getconnection", "jdbc"];

      if (lowerCalls.some(call => nosqlIndicators.some(indicator => call.includes(indicator)))) {
        add("database_nosql", "nosql", filePath, facts.functionCalls, 0.90);
      }
      if (lowerCalls.some(call => sqlIndicators.some(indicator => call.includes(indicator)))) {
        add("database_sql", "sql", filePath, facts.functionCalls, 0.90);
      }
    }

    void files;

    return Array.from(stores.values());
  }

  private deriveExposures(
    files: RepositoryFileDescriptor[],
    sourceFactsByFile: Map<string, SourceFactSet>,
    dependencyAnalysis: DependencyAnalysisResult,
  ): ExposureDescriptor[] {
    const exposures: ExposureDescriptor[] = [];

    for (const [filePath, facts] of sourceFactsByFile.entries()) {
      if (
    facts.routes.length > 0
) {

    exposures.push({

        id:
            `exposure:${filePath}`,

        kind:
            "api",

        route:
            facts.routes
                .map(
                    route =>
                        `${route.method} ${route.path}`
                )
                .join(", "),

        protocol:
            "http",

        authentication:
            facts.routes.some(
                route =>
                    route.authenticationHint ===
                    "required"
            )
                ? "required"
                : "unknown",

        files:
            [filePath],

        evidence:
            facts.routes.map(
                route =>
                    `${route.method} ${route.path}`
            ),

        confidence:
            0.95

    });

}
    }


    void files;
    return exposures;
  }

  private deriveModuleName(file: RepositoryFileDescriptor, files: RepositoryFileDescriptor[]): string {
    const manifestRoot = this.findModuleRoot(file.relativePath, files.filter(candidate => candidate.isManifest).map(candidate => path.posix.dirname(candidate.relativePath)));
    return manifestRoot === "." ? "root" : manifestRoot;
  }

  private findModuleRoot(relativePath: string, manifestRoots: string[]): string {
    const normalized = path.posix.normalize(relativePath);
    const matchingRoot = manifestRoots
      .filter(root => normalized.startsWith(root === "." ? "" : `${root}/`))
      .sort((left, right) => right.length - left.length)[0];

    return matchingRoot || path.posix.dirname(normalized) || ".";
  }

  private isLocalImport(specifier: string): boolean {
    return specifier.startsWith(".") || specifier.startsWith("/");
  }

  private normalizePackageName(specifier: string): string | undefined {
    if (!specifier || this.isLocalImport(specifier) || specifier.startsWith("file:")) {
      return undefined;
    }

    if (specifier.startsWith("@")) {
      const [scope, packageName] = specifier.split("/");
      return packageName ? `${scope}/${packageName}` : scope;
    }

    return specifier.split("/")[0];
  }

  private resolveLocalImport(file: RepositoryFileDescriptor, importSpecifier: string, files: RepositoryFileDescriptor[]): RepositoryFileDescriptor | undefined {
    const baseDirectory = path.posix.dirname(file.relativePath);
    const normalized = path.posix.normalize(path.posix.join(baseDirectory, importSpecifier));
    const candidates = [
      normalized,
      `${normalized}.ts`,
      `${normalized}.tsx`,
      `${normalized}.js`,
      `${normalized}.jsx`,
      `${normalized}.mjs`,
      `${normalized}.cjs`,
      `${normalized}.py`,
      `${normalized}.java`,
      `${normalized}.go`,
      `${normalized}.cs`,
      `${normalized}.rb`,
      `${normalized}.php`,
      `${normalized}.rs`,
      path.posix.join(normalized, "index.ts"),
      path.posix.join(normalized, "index.tsx"),
      path.posix.join(normalized, "index.js"),
      path.posix.join(normalized, "index.py"),
    ];

    for (const candidate of candidates) {
      const resolved = files.find(entry => entry.relativePath === candidate || entry.relativePath === candidate.replace(/^\.\//, ""));
      if (resolved) {
        return resolved;
      }
    }

    return undefined;
  }
}
