export class SeverityEngine {

    calculate(
        findings: any[]
    ) {

        let score = 0;

        for (
            const finding
            of findings
        ) {

            switch (
                finding.severity
            ) {

                case "CRITICAL":
                    score += 10;
                    break;

                case "HIGH":
                    score += 7;
                    break;

                case "MEDIUM":
                    score += 4;
                    break;

                case "LOW":
                    score += 1;
                    break;

            }

        }

        return score;

    }

}