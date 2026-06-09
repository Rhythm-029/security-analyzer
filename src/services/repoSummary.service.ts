export class RepositorySummaryService {

    summarize(files: any[]) {

        const modules =
            new Set<string>();

        const technologies =
            new Set<string>();

        const securityAreas =
            new Set<string>();

        const dependencies:
            Record<string, string[]>
            = {};

        for (const file of files) {

            /*
            -----------------------
            MODULES
            -----------------------
            */

            if (
                file.context?.module
            ) {

                modules.add(
                    file.context.module
                );

            }

            /*
-----------------------
TECHNOLOGIES
-----------------------
*/

if (

    file.path.endsWith(
        "package.json"
    ) ||

    file.path.endsWith(
        "pom.xml"
    ) ||

    file.path.endsWith(
        "requirements.txt"
    ) ||

    file.path.endsWith(
        "go.mod"
    ) ||

    file.path.endsWith(
        ".csproj"
    )

) {

    if (
        file.context?.technologies
    ) {

        for (
            const tech of
            file.context.technologies
        ) {

            technologies.add(
                tech
            );

        }

    }

}
            /*
            -----------------------
            SECURITY AREAS
            -----------------------
            */

            if (
                file.context?.securityAreas
            ) {

                for (
                    const area of
                    file.context.securityAreas
                ) {

                    securityAreas.add(
                        area
                    );

                }

            }

            /*
            -----------------------
            DEPENDENCIES
            -----------------------
            */

            if (
                file.context?.ast?.imports
            ) {

                dependencies[
                    file.path
                ] =
                    file.context.ast.imports;

            }

        }

        return {

            totalFiles:
                files.length,

            modules:
                Array.from(
                    modules
                ),

            technologies:
                Array.from(
                    technologies
                ),

            securityAreas:
                Array.from(
                    securityAreas
                ),

            dependencies

        };

    }

}