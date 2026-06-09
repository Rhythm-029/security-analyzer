import { SECURITY_SIGNALS }
from "../signals/security.signals";

export class SecurityAnalyzer {

    analyze(content: string) {

        const areas: string[] = [];

        for (
            const [area, signals]
            of Object.entries(
                SECURITY_SIGNALS
            )
        ) {

            let detected = false;

            for (
                const keyword
                of signals.keywords
            ) {

                if (
                    content.includes(keyword)
                ) {

                    detected = true;
                    break;

                }

            }

            for (
                const pattern
                of signals.patterns
            ) {

                if (
                    content.includes(pattern)
                ) {

                    detected = true;
                    break;

                }

            }

            if (detected) {

                areas.push(area);

            }

        }

        return areas;

    }

}