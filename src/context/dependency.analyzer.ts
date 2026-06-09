export class DependencyAnalyzer {

    analyze(
        fileName: string,
        content: string
    ): string[] {

        try {

            if (
                fileName.endsWith(
                    "package.json"
                )
            ) {

                const packageJson =
                    JSON.parse(content);

                return Object.keys({

                    ...packageJson.dependencies,

                    ...packageJson.devDependencies

                });

            }

        } catch {

            return [];

        }

        return [];

    }

}