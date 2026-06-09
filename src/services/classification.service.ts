export class ClassificationService {

    classify(filePath: string): string {

        const fileName = filePath.split("/").pop() || "";

        const extension =
            fileName.includes(".")
                ? "." + fileName.split(".").pop()
                : "";
// dependency

        const dependencyFiles = [
            "package.json",
            "package-lock.json",
            "requirements.txt",
            "pom.xml",
            "composer.json"
        ];

        if (dependencyFiles.includes(fileName)) {
            return "dependency";
        }
  // config

        const configExtensions = [
            ".env",
            ".yaml",
            ".yml",
            ".ini",
            ".conf"
        ];

        if (configExtensions.includes(extension)) {
            return "configuration";
        }
 // source code

        const sourceExtensions = [
            ".ts",
            ".js",
            ".jsx",
            ".tsx",
            ".py",
            ".java",
            ".go",
            ".cs"
        ];

        if (sourceExtensions.includes(extension)) {
            return "source_code";
        }
 // docs

        const docsExtensions = [
            ".md",
            ".txt"
        ];

        if (docsExtensions.includes(extension)) {
            return "documentation";
        }

 // infra

        if (
            fileName === "Dockerfile" ||
            fileName.includes("docker-compose")
        ) {
            return "infrastructure";
        }

        return "unknown";
    }

}