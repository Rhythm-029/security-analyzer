import fs from "fs/promises";
import fg from "fast-glob";
import { ClassificationService } from "./classification.service";

export class RepositoryScannerService {
  private classifier = new ClassificationService();

    async scan(path: string) {

        const files = await fg("**/*", {
  cwd: path,
  onlyFiles: true,
  dot: true,
  ignore: [
  "node_modules/**",
  ".git/**",
  "dist/**",
  "build/**",
  "coverage/**",

  "**/.DS_Store",
  "**/*.png",
  "**/*.jpg",
  "**/*.jpeg",
  "**/*.gif",
  "**/*.webp",
  "**/*.ico",

  "**/package-lock.json",
  "**/yarn.lock",
  "**/pnpm-lock.yaml"
]
});

        const fileDetails = [];

for (const file of files) {

    const fullPath = `${path}/${file}`;

    try {

        const content = await fs.readFile(
            fullPath,
            "utf-8"
        );

        const fileType =
    this.classifier.classify(file);

fileDetails.push({
    path: file,
    absolutePath: fullPath,
    extension: file.split(".").pop(),
    type: fileType,
    size: content.length,
    content
});

    } catch (error) {

        console.log(`Could not read ${file}`);

    }
}

return fileDetails;
    }

}