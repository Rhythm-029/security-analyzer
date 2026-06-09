export class CapabilityAnalyzer {

    analyze(
        ast: any
    ): string[] {

        const capabilities =
            new Set<string>();

        const calls =
            ast?.functionCalls || [];

        for (
            const call of calls
        ) {

            if (
                call.includes("jwt")
            ) {

                capabilities.add(
                    "authentication"
                );

            }

            if (
                call.includes("bcrypt")
            ) {

                capabilities.add(
                    "password_management"
                );

            }

            if (
                call.includes("mongoose")
            ) {

                capabilities.add(
                    "database_access"
                );

            }

            if (
                call.includes("router.")
            ) {

                capabilities.add(
                    "api_exposure"
                );

            }

        }

        if (
            ast?.envVariables?.length
        ) {

            capabilities.add(
                "secrets_management"
            );

        }

        return Array.from(
            capabilities
        );

    }

}