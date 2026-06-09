export class RepositoryModuleAnalyzer {

    analyze(
        filePath: string
    ): string[] {

        const modules =
            new Set<string>();

        const lower =
            filePath.toLowerCase();

        if (
            lower.includes(
                "/controller"
            )
        ) {

            modules.add(
                "controller"
            );

        }

        if (
            lower.includes(
                "/route"
            )
        ) {

            modules.add(
                "route"
            );

        }

        if (
            lower.includes(
                "/service"
            )
        ) {

            modules.add(
                "service"
            );

        }

        if (
            lower.includes(
                "/parser"
            )
        ) {

            modules.add(
                "parser"
            );

        }

        if (
            lower.includes(
                "/security"
            )
        ) {

            modules.add(
                "security"
            );

        }

        return Array.from(
            modules
        );

    }

}