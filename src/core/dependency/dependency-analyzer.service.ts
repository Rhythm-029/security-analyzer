import path from "path";
import {
  DependencyAnalysisResult,
  DependencyDescriptor,
  DependencyManifestFact,
  DependencyStatus,
  RepositoryFileDescriptor,
  SourceFactSet,
} from "../domain/appsec.types";
import { DependencyAnalyzerContract } from "../contracts/appsec.contracts";

type ManifestDependencyBucket = {
  runtime: Record<string, string | undefined>;
  dev: Record<string, string | undefined>;
  peer: Record<string, string | undefined>;
  optional: Record<string, string | undefined>;
};

const KNOWN_MANIFEST_FILES = new Set([
  "package.json",
  "composer.json",
  "Cargo.toml",
  "requirements.txt",
  "pyproject.toml",
  "pom.xml",
  "go.mod",
  "Gemfile",
  "pubspec.yaml",
]);

export class DependencyAnalyzerService implements DependencyAnalyzerContract {
  async analyze(
    files: RepositoryFileDescriptor[],
    fileContents: Map<string, string>,
    sourceFactsByFile: Map<string, SourceFactSet>,
  ): Promise<DependencyAnalysisResult> {
    const manifests: DependencyManifestFact[] = [];

    for (const file of files) {
      if (!file.isManifest && !KNOWN_MANIFEST_FILES.has(file.fileName) && !file.fileName.endsWith(".csproj")) {
        continue;
      }

      const content = fileContents.get(file.absolutePath);
      if (!content) {
        continue;
      }

      const manifest = this.parseManifest(file, content);
      if (manifest) {
        manifests.push(manifest);
      }
    }

    const importsByFile = new Map<string, string[]>();
    for (const [filePath, facts] of sourceFactsByFile.entries()) {
      importsByFile.set(filePath, facts.imports);
    }

    const allUsedDependencies = new Map<string, Set<string>>();
    for (const [filePath, imports] of importsByFile.entries()) {
      for (const importSpecifier of imports) {
        const packageName = this.normalizeDependencyName(importSpecifier);
        if (!packageName) {
          continue;
        }

        if (!allUsedDependencies.has(packageName)) {
          allUsedDependencies.set(packageName, new Set<string>());
        }

        allUsedDependencies.get(packageName)?.add(filePath);
      }
    }

    const dependencies: DependencyDescriptor[] = [];
    const declaredDependencyNames = new Set<string>();
    for (const manifest of manifests) {
      const manifestDependencies = [
        ...manifest.declaredDependencies,
        ...manifest.devDependencies,
        ...manifest.peerDependencies,
        ...manifest.optionalDependencies,
        ...manifest.lockfileDependencies,
      ];

      for (const dependency of manifestDependencies) {
        declaredDependencyNames.add(dependency.name.toLowerCase());
      }

      for (const dependency of manifestDependencies) {
        const usedByFiles = this.resolveUsage(dependency.name, allUsedDependencies, importsByFile);
        const status = this.resolveStatus(dependency, usedByFiles.length > 0);
        dependencies.push({
          ...dependency,
          usedByFiles,
          status,
        });
      }
    }

    const missingDependencies = new Map<string, Set<string>>();
    for (const [filePath, imports] of importsByFile.entries()) {
      for (const importSpecifier of imports) {
        const packageName = this.normalizeDependencyName(importSpecifier);
        if (!packageName || this.isBuiltInNodeModule(packageName)) {
          continue;
        }

        if (declaredDependencyNames.has(packageName.toLowerCase())) {
          continue;
        }

        if (!missingDependencies.has(packageName)) {
          missingDependencies.set(packageName, new Set<string>());
        }

        missingDependencies.get(packageName)?.add(filePath);
      }
    }

    for (const [packageName, usedFiles] of missingDependencies.entries()) {
      const firstFile = Array.from(usedFiles)[0];
      dependencies.push({
        id: `missing:nodejs:${packageName}`,
        name: packageName,
        ecosystem: "nodejs",
        scope: "runtime",
        status: "missing",
        sourceFile: firstFile,
        usedByFiles: Array.from(usedFiles),
        version: undefined,
        evidence: Array.from(usedFiles),
      });
    }

    return {
      manifests,
      dependencies,
    };
  }

  private parseManifest(file: RepositoryFileDescriptor, content: string): DependencyManifestFact | undefined {
    const fileName = file.fileName;

    if (fileName === "package.json") {
      return this.parseJsonManifest(file.absolutePath, content, "nodejs", {
        runtime: this.objectToVersions(this.safeJsonParse(content)?.dependencies),
        dev: this.objectToVersions(this.safeJsonParse(content)?.devDependencies),
        peer: this.objectToVersions(this.safeJsonParse(content)?.peerDependencies),
        optional: this.objectToVersions(this.safeJsonParse(content)?.optionalDependencies),
      });
    }

    if (fileName === "composer.json") {
      return this.parseJsonManifest(file.absolutePath, content, "php", {
        runtime: this.objectToVersions(this.safeJsonParse(content)?.require),
        dev: this.objectToVersions(this.safeJsonParse(content)?.["require-dev"]),
        peer: {},
        optional: {},
      });
    }

    if (fileName === "Cargo.toml") {
      return this.parseCargoToml(file.absolutePath, content);
    }

    if (fileName === "requirements.txt") {
      return this.parseRequirementsTxt(file.absolutePath, content);
    }

    if (fileName === "go.mod") {
      return this.parseGoMod(file.absolutePath, content);
    }

    if (fileName === "Gemfile") {
      return this.parseGemfile(file.absolutePath, content);
    }

    if (fileName === "pyproject.toml") {
      return this.parsePyProject(file.absolutePath, content);
    }

    if (fileName === "pom.xml") {
      return this.parsePomXml(file.absolutePath, content);
    }

    if (fileName.endsWith(".csproj")) {
      return this.parseCsproj(file.absolutePath, content);
    }

    if (fileName === "pubspec.yaml") {
      return this.parsePubspec(file.absolutePath, content);
    }

    return undefined;
  }

  private parseJsonManifest(
    manifestFile: string,
    content: string,
    ecosystem: string,
    buckets: ManifestDependencyBucket,
  ): DependencyManifestFact {
    return {
      ecosystem,
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, ecosystem, "runtime", buckets.runtime),
      devDependencies: this.toDependencies(manifestFile, ecosystem, "dev", buckets.dev),
      peerDependencies: this.toDependencies(manifestFile, ecosystem, "peer", buckets.peer),
      optionalDependencies: this.toDependencies(manifestFile, ecosystem, "optional", buckets.optional),
      lockfileDependencies: [],
    };
  }

  private parseRequirementsTxt(manifestFile: string, content: string): DependencyManifestFact {
    const dependencies = new Map<string, string | undefined>();

    content.split(/\r?\n/).forEach(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) {
        return;
      }

      const match = trimmed.match(/^([A-Za-z0-9_.\-@/]+)(?:[<>=!~].*)?$/);
      if (match) {
        dependencies.set(match[1], undefined);
      }
    });

    return {
      ecosystem: "python",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, "python", "runtime", Object.fromEntries(dependencies)),
      devDependencies: [],
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private parseGoMod(manifestFile: string, content: string): DependencyManifestFact {
    const dependencyMap = new Map<string, string | undefined>();
    const lines = content.split(/\r?\n/);
    let inRequireBlock = false;

    for (const rawLine of lines) {
      const line = rawLine.trim();

      if (line.startsWith("require (") || line === "require(") {
        inRequireBlock = true;
        continue;
      }

      if (inRequireBlock && line === ")") {
        inRequireBlock = false;
        continue;
      }

      const requireMatch = line.match(/^require\s+([^\s]+)\s+([^\s]+)$/);
      if (requireMatch) {
        dependencyMap.set(requireMatch[1], requireMatch[2]);
        continue;
      }

      if (inRequireBlock) {
        const blockMatch = line.match(/^([^\s]+)\s+([^\s]+)$/);
        if (blockMatch) {
          dependencyMap.set(blockMatch[1], blockMatch[2]);
        }
      }
    }

    return {
      ecosystem: "go",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, "go", "runtime", Object.fromEntries(dependencyMap)),
      devDependencies: [],
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private parseCargoToml(manifestFile: string, content: string): DependencyManifestFact {
    const sections = this.parseTomlDependencySections(content);
    return {
      ecosystem: "rust",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, "rust", "runtime", sections.runtime),
      devDependencies: this.toDependencies(manifestFile, "rust", "dev", sections.dev),
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private parsePyProject(manifestFile: string, content: string): DependencyManifestFact {
    const sections = this.parseTomlDependencySections(content);
    return {
      ecosystem: "python",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, "python", "runtime", sections.runtime),
      devDependencies: this.toDependencies(manifestFile, "python", "dev", sections.dev),
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private parseGemfile(manifestFile: string, content: string): DependencyManifestFact {
    const dependencies = new Map<string, string | undefined>();
    content.split(/\r?\n/).forEach(line => {
      const match = line.match(/^\s*gem\s+["']([^"']+)["'](?:\s*,\s*["']([^"']+)["'])?/);
      if (match) {
        dependencies.set(match[1], match[2]);
      }
    });

    return {
      ecosystem: "ruby",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, "ruby", "runtime", Object.fromEntries(dependencies)),
      devDependencies: [],
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private parsePomXml(manifestFile: string, content: string): DependencyManifestFact {
    const dependencies = new Map<string, string | undefined>();
    const dependencyBlocks = content.match(/<dependency>[\s\S]*?<\/dependency>/g) || [];

    for (const block of dependencyBlocks) {
      const groupId = this.firstMatch(block, /<groupId>([^<]+)<\/groupId>/);
      const artifactId = this.firstMatch(block, /<artifactId>([^<]+)<\/artifactId>/);
      const version = this.firstMatch(block, /<version>([^<]+)<\/version>/);
      if (groupId || artifactId) {
        dependencies.set([groupId, artifactId].filter(Boolean).join(":"), version);
      }
    }

    return {
      ecosystem: "java",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, "java", "runtime", Object.fromEntries(dependencies)),
      devDependencies: [],
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private parseCsproj(manifestFile: string, content: string): DependencyManifestFact {
    const dependencies = new Map<string, string | undefined>();
    const references = content.match(/<PackageReference[^>]*>/g) || [];

    for (const reference of references) {
      const include = this.firstMatch(reference, /Include="([^"]+)"/);
      const version = this.firstMatch(reference, /Version="([^"]+)"/);
      if (include) {
        dependencies.set(include, version);
      }
    }

    return {
      ecosystem: ".net",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, ".net", "runtime", Object.fromEntries(dependencies)),
      devDependencies: [],
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private parsePubspec(manifestFile: string, content: string): DependencyManifestFact {
    const dependencies = new Map<string, string | undefined>();
    const lines = content.split(/\r?\n/);
    let inDependencies = false;

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (line.startsWith("dependencies:")) {
        inDependencies = true;
        continue;
      }
      if (inDependencies && /^[A-Za-z_\-]+:/.test(line)) {
        const [name, rest] = line.split(":", 2);
        dependencies.set(name.trim(), rest?.trim() || undefined);
      }
    }

    return {
      ecosystem: "dart",
      manifestFile,
      declaredDependencies: this.toDependencies(manifestFile, "dart", "runtime", Object.fromEntries(dependencies)),
      devDependencies: [],
      peerDependencies: [],
      optionalDependencies: [],
      lockfileDependencies: [],
    };
  }

  private objectToVersions(input: unknown): Record<string, string | undefined> {
    if (!input || typeof input !== "object") {
      return {};
    }

    return Object.entries(input as Record<string, unknown>).reduce<Record<string, string | undefined>>((accumulator, [key, value]) => {
      accumulator[key] = typeof value === "string" ? value : undefined;
      return accumulator;
    }, {});
  }

  private toDependencies(
    manifestFile: string,
    ecosystem: string,
    scope: "runtime" | "dev" | "peer" | "optional",
    dependencies: Record<string, string | undefined>,
  ): DependencyDescriptor[] {
    return Object.entries(dependencies).map(([name, version]) => ({
      id: `${ecosystem}:${name}`,
      name,
      version,
      ecosystem,
      scope,
      status: "declared_unused" as DependencyStatus,
      sourceFile: manifestFile,
      usedByFiles: [],
      evidence: [manifestFile],
    }));
  }

  private normalizeDependencyName(specifier: string): string | undefined {
    if (!specifier || specifier.startsWith(".") || specifier.startsWith("/") || specifier.startsWith("file:")) {
      return undefined;
    }

    if (specifier.startsWith("@")) {
      const [scope, packageName] = specifier.split("/");
      return packageName ? `${scope}/${packageName}` : scope;
    }

    return specifier.split("/")[0];
  }

  private isBuiltInNodeModule(name: string): boolean {
    return new Set([
      "fs",
      "path",
      "url",
      "os",
      "http",
      "https",
      "crypto",
      "util",
      "stream",
      "events",
      "child_process",
      "module",
      "buffer",
      "zlib",
      "assert",
      "net",
      "tls",
      "dns",
      "readline",
      "timers",
      "perf_hooks",
      "querystring",
    ]).has(name.replace(/^node:/, ""));
  }

  private resolveUsage(
    dependencyName: string,
    allUsedDependencies: Map<string, Set<string>>,
    importsByFile: Map<string, string[]>,
  ): string[] {
    const usedFiles = new Set<string>();

    for (const [packageName, fileSet] of allUsedDependencies.entries()) {
      if (this.matchesDependencyName(dependencyName, packageName)) {
        fileSet.forEach(file => usedFiles.add(file));
      }
    }

    if (usedFiles.size === 0) {
      for (const [filePath, imports] of importsByFile.entries()) {
        if (imports.some(importSpecifier => this.matchesDependencyName(dependencyName, this.normalizeDependencyName(importSpecifier) || importSpecifier))) {
          usedFiles.add(filePath);
        }
      }
    }

    return Array.from(usedFiles);
  }

  private matchesDependencyName(left: string, right: string): boolean {
    const normalizedLeft = left.toLowerCase();
    const normalizedRight = right.toLowerCase();

    return normalizedLeft === normalizedRight
      || normalizedRight.startsWith(`${normalizedLeft}/`)
      || normalizedLeft.startsWith(`${normalizedRight}/`);
  }

  private resolveStatus(dependency: DependencyDescriptor, hasUsage: boolean): DependencyStatus {
    if (hasUsage) {
      return "declared_used";
    }

    return dependency.scope === "transitive" ? "transitive" : "declared_unused";
  }

  private parseTomlDependencySections(content: string): { runtime: Record<string, string | undefined>; dev: Record<string, string | undefined> } {
    const runtime: Record<string, string | undefined> = {};
    const dev: Record<string, string | undefined> = {};
    let currentSection: "runtime" | "dev" | undefined;

    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (line.startsWith("[dependencies]")) {
        currentSection = "runtime";
        continue;
      }
      if (line.startsWith("[dev-dependencies]") || line.startsWith("[tool.poetry.dev-dependencies]")) {
        currentSection = "dev";
        continue;
      }
      if (line.startsWith("[")) {
        currentSection = undefined;
        continue;
      }

      const match = line.match(/^([A-Za-z0-9_.\-@/]+)\s*=\s*(.+)$/);
      if (!match || !currentSection) {
        continue;
      }

      const name = match[1];
      const value = match[2].replace(/^["']|["']$/g, "");
      if (currentSection === "runtime") {
        runtime[name] = value;
      } else {
        dev[name] = value;
      }
    }

    return { runtime, dev };
  }

  private safeJsonParse(content: string): any {
    try {
      return JSON.parse(content);
    } catch {
      return undefined;
    }
  }

  private firstMatch(input: string, regex: RegExp): string | undefined {
    const match = input.match(regex);
    return match?.[1];
  }
}
