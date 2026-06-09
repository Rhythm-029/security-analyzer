export class SecurityReportService {

    generate(
        repositorySummary: any,
        semgrepFindings: any[],
        riskScore: number
    ) {

        const critical =
            semgrepFindings.filter(
                finding =>
                    finding.severity === "ERROR"
            ).length;

        const high =
            semgrepFindings.filter(
                finding =>
                    finding.severity === "WARNING"
            ).length;

        const medium = 0;

        const low = 0;

        const recommendations: string[] = [];

        if (critical > 0) {

            recommendations.push(
                "Fix critical vulnerabilities immediately."
            );

        }

        if (high > 0) {

            recommendations.push(
                "Review and remediate high-risk findings."
            );

        }

        if (
            semgrepFindings.length === 0
        ) {

            recommendations.push(
                "No security vulnerabilities detected."
            );

        }

        return {

            repository: {

                totalFiles:
                    repositorySummary.totalFiles,

                technologies:
                    repositorySummary.technologies,

                modules:
                    repositorySummary.modules,

                securityAreas:
                    repositorySummary.securityAreas

            },

            securityOverview: {

                riskScore,

                critical,

                high,

                medium,

                low

            },

            findings:

                semgrepFindings.map(
                    finding => ({

                        severity:
                            finding.severity,

                        ruleId:
                            finding.ruleId,

                        file:
                            finding.file,

                        line:
                            finding.line,

                        message:
                            finding.message

                    })
                ),

            recommendations

        };

    }

}