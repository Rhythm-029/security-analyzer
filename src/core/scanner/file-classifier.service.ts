import { FileKind, RepositoryFileDescriptor, SourceLanguage } from "../domain/appsec.types";

const MANIFEST_FILES = new Set([
  "package.json",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "requirements.txt",
  "pyproject.toml",
  "setup.py",
  "pom.xml",
  "build.gradle",
  "build.gradle.kts",
  "go.mod",
  "go.sum",
  "Cargo.toml",
  "Cargo.lock",
  "composer.json",
  "composer.lock",
  "Gemfile",
  "Gemfile.lock",
  "pubspec.yaml",
  "pubspec.lock",
  "*.csproj",
  "*.sln",
]);

const SOURCE_LANGUAGE_BY_EXTENSION: Record<string, SourceLanguage> = {
  ts: "typescript",
  tsx: "typescript",
  js: "javascript",
  jsx: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  java: "java",
  py: "python",
  go: "go",
  cs: "csharp",
  fs: "fsharp",
  fsx: "fsharp",
  php: "php",
  rb: "ruby",
  rs: "rust",
  kt: "kotlin",
  kts: "kotlin",
  scala: "scala",
  yaml: "yaml",
  yml: "yaml",
};

const BINARY_EXTENSIONS = new Set([
  "png",
  "jpg",
  "jpeg",
  "gif",
  "webp",
  "ico",
  "pdf",
  "zip",
  "gz",
  "tgz",
  "7z",
  "jar",
  "war",
  "exe",
  "dll",
  "so",
  "dylib",
  "class",
]);

export class FileClassifierService {
  classify(relativePath: string, sizeBytes: number): Pick<RepositoryFileDescriptor, "kind" | "language" | "isBinary" | "isManifest" | "isSource" | "isConfiguration" | "isGenerated"> & { extension: string } {
    const normalizedPath = relativePath.replace(/\\/g, "/");
    const fileName = normalizedPath.split("/").pop() || normalizedPath;
    const extension = this.getExtension(fileName);
    const isBinary = BINARY_EXTENSIONS.has(extension);
    const isManifest = this.isManifestFile(fileName);
    const isSource = this.isSourceFile(extension);
    const isConfiguration = this.isConfigurationFile(fileName, extension);
    const isGenerated = /(^|[./_-])(generated|gen|dist|build|target)([./_-]|$)/i.test(normalizedPath);

    let kind: FileKind = "unknown";
    let language: SourceLanguage | undefined;

    if (isBinary) {
      kind = "binary";
    } else if (isManifest) {
      kind = "manifest";
    } else if (isSource) {
      kind = "source";
      language = SOURCE_LANGUAGE_BY_EXTENSION[extension];
    } else if (isConfiguration) {
      kind = "config";
    } else if (this.isDocumentationFile(fileName, extension)) {
      kind = "documentation";
    }

    if (isGenerated && kind === "source") {
      kind = "generated";
    }

    return {
      extension,
      kind,
      language,
      isBinary,
      isManifest,
      isSource,
      isConfiguration,
      isGenerated,
    };
  }

  private getExtension(fileName: string): string {
    if (fileName.includes(".")) {
      return fileName.split(".").pop()?.toLowerCase() || "";
    }

    return fileName.toLowerCase();
  }

  private isManifestFile(fileName: string): boolean {
    if (MANIFEST_FILES.has(fileName)) {
      return true;
    }

    return /\.csproj$/i.test(fileName) || /\.sln$/i.test(fileName);
  }

  private isSourceFile(extension: string): boolean {
    return Object.prototype.hasOwnProperty.call(SOURCE_LANGUAGE_BY_EXTENSION, extension);
  }

  private isConfigurationFile(fileName: string, extension: string): boolean {
    return ["json", "toml", "yaml", "yml", "xml", "ini", "conf", "env"].includes(extension)
      || fileName === "Dockerfile"
      || fileName === "docker-compose.yml"
      || fileName === "docker-compose.yaml"
      || fileName === ".env"
      || fileName.endsWith(".tf")
      || fileName.endsWith(".tfvars");
  }

  private isDocumentationFile(fileName: string, extension: string): boolean {
    return ["md", "mdx", "rst", "txt"].includes(extension) || /^readme(\.|$)/i.test(fileName);
  }
}
