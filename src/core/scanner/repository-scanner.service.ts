import fs from "fs/promises";
import path from "path";
import fg from "fast-glob";
import { FileClassifierService } from "./file-classifier.service";
import { RepositoryFileDescriptor, ScanOptions } from "../domain/appsec.types";
import { RepositoryScannerContract } from "../contracts/appsec.contracts";
import { normalizeRepositoryPath } from "../../config/repository.config";

const DEFAULT_IGNORES = [
  "**/.git/**",
  "**/node_modules/**",
  "**/dist/**",
  "**/build/**",
  "**/coverage/**",
  "**/.DS_Store",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.webp",
  "**/*.ico",
  "**/*.min.js",
  "**/*.min.css",
];

export class RepositoryScannerService implements RepositoryScannerContract {
  private readonly classifier = new FileClassifierService();

  async scan(repositoryPath: string, options?: ScanOptions): Promise<RepositoryFileDescriptor[]> {
    const resolvedRepositoryPath = normalizeRepositoryPath(repositoryPath);
    const includeGeneratedFiles = options?.includeGeneratedFiles ?? false;
    const maxFileSizeBytes = options?.maxFileSizeBytes ?? 5 * 1024 * 1024;

    if (!resolvedRepositoryPath) {
      return [];
    }

    try {
      await fs.access(resolvedRepositoryPath);
    } catch {
      return [];
    }

    const entries = await fg("**/*", {
      cwd: resolvedRepositoryPath,
      dot: true,
      onlyFiles: true,
      followSymbolicLinks: false,
      ignore: DEFAULT_IGNORES,
    });

    const descriptors: RepositoryFileDescriptor[] = [];

    for (const relativePath of entries) {
      const absolutePath = path.join(resolvedRepositoryPath, relativePath);

      try {
        const stat = await fs.stat(absolutePath);
        if (stat.size > maxFileSizeBytes) {
          continue;
        }

        const classification = this.classifier.classify(relativePath, stat.size);
        if (!includeGeneratedFiles && classification.isGenerated) {
          continue;
        }

        descriptors.push({
          absolutePath,
          relativePath,
          fileName: path.basename(relativePath),
          extension: classification.extension,
          kind: classification.kind,
          language: classification.language,
          sizeBytes: stat.size,
          isBinary: classification.isBinary,
          isManifest: classification.isManifest,
          isSource: classification.isSource,
          isConfiguration: classification.isConfiguration,
          isGenerated: classification.isGenerated,
        });
      } catch {
        continue;
      }
    }

    return descriptors;
  }

  async readText(absolutePath: string): Promise<string> {
    return fs.readFile(absolutePath, "utf-8");
  }
}
