export class TechnologyAnalyzer {

    analyze(
        fileName: string,
        content: string
    ): string[] {

        const dependencyTechnologies =
            this.detectFromDependencies(
                fileName,
                content
            );

        if (
            dependencyTechnologies.length > 0
        ) {

            return dependencyTechnologies;

        }

        const importTechnologies =
            this.detectFromImports(
                content
            );

        if (
            importTechnologies.length > 0
        ) {

            return importTechnologies;

        }

        return this.detectFromKeywords(
            content
        );

    }

    private detectFromDependencies(
        fileName: string,
        content: string
    ): string[] {
        console.log(
    "Technology Scan:",
    fileName
);

        const technologies =
            new Set<string>();

        try {

            if (
                fileName.endsWith(
                    "package.json"
                )
            ) {
                console.log(
                     "Found package.json"
                           );

                const packageJson =
                    JSON.parse(content);

                const dependencies = {

                    ...packageJson.dependencies,

                    ...packageJson.devDependencies

                };

                technologies.add(
                    "nodejs"
                );

                if (
                    dependencies["express"]
                ) {

                    technologies.add(
                        "express"
                    );

                }

                if (
                    dependencies["mongoose"]
                ) {

                    technologies.add(
                        "mongodb"
                    );

                }

                if (
                    dependencies["jsonwebtoken"]
                ) {

                    technologies.add(
                        "jwt"
                    );

                }

                if (
                    dependencies["typescript"]
                ) {

                    technologies.add(
                        "typescript"
                    );

                }

            }

            if (
                fileName.endsWith(
                    "pom.xml"
                )
            ) {

                technologies.add(
                    "java"
                );

                if (
                    content.includes(
                        "spring-boot"
                    )
                ) {

                    technologies.add(
                        "springboot"
                    );

                }

            }

            if (
                fileName.endsWith(
                    "requirements.txt"
                )
            ) {

                technologies.add(
                    "python"
                );

                if (
                    content.includes(
                        "django"
                    )
                ) {

                    technologies.add(
                        "django"
                    );

                }

                if (
                    content.includes(
                        "flask"
                    )
                ) {

                    technologies.add(
                        "flask"
                    );

                }

                if (
                    content.includes(
                        "fastapi"
                    )
                ) {

                    technologies.add(
                        "fastapi"
                    );

                }

            }

            if (
                fileName.endsWith(
                    "go.mod"
                )
            ) {

                technologies.add(
                    "golang"
                );

            }

            if (
                fileName.endsWith(
                    ".csproj"
                )
            ) {

                technologies.add(
                    ".net"
                );

            }

        } catch {

            return [];

        }

        return Array.from(
            technologies
        );

    }

    private detectFromImports(
        content: string
    ): string[] {

        const technologies =
            new Set<string>();

        if (
            content.includes(
                'from "express"'
            ) ||
            content.includes(
                "require('express')"
            )
        ) {

            technologies.add(
                "express"
            );

        }

        if (
            content.includes(
                "jsonwebtoken"
            )
        ) {

            technologies.add(
                "jwt"
            );

        }

        if (
            content.includes(
                "mongoose"
            )
        ) {

            technologies.add(
                "mongodb"
            );

        }

        return Array.from(
            technologies
        );

    }

    private detectFromKeywords(
        content: string
    ): string[] {

        const technologies =
            new Set<string>();

        if (
            content.includes(
                "jwt.sign("
            ) ||
            content.includes(
                "jwt.verify("
            )
        ) {

            technologies.add(
                "jwt"
            );

        }

        if (
            content.includes(
                "mongoose.connect("
            )
        ) {

            technologies.add(
                "mongodb"
            );

        }

        return Array.from(
            technologies
        );

    }

}