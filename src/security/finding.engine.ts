import {
    SecurityFinding
}
from "./finding.types";

export class FindingEngine {

    analyze(
        file: any
    ): SecurityFinding[] {

        const findings:
            SecurityFinding[] = [];

        /*
        --------------------------------
        Missing Authentication
        --------------------------------
        */

        if (

            file.context?.role ===
            "route"

        ) {

            const routes =
                file.context.ast
                    ?.routes || [];

            for (
                const route
                of routes
            ) {

                if (
                    route.middleware
                        .length === 0
                ) {

                    findings.push({

                        type:
                            "MissingAuthentication",

                        severity:
                            "HIGH",

                        file:
                            file.path,

                        description:
                            `Route ${route.path} has no middleware protection`

                    });

                }

            }

        }

        return findings;

    }

}