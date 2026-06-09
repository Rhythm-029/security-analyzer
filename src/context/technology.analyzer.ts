import { TECHNOLOGY_SIGNALS }
from "./technology.signals";

export class TechnologyAnalyzer {

    analyze(content: string) {

        const technologies: string[] = [];

        for (
            const [technology, signals]
            of Object.entries(
                TECHNOLOGY_SIGNALS
            )
        ) {

            let detected = false;

            for (
                const keyword
                of signals.keywords
            ) {

                if (
                    content.includes(
                        keyword
                    )
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
                    content.includes(
                        pattern
                    )
                ) {

                    detected = true;
                    break;

                }

            }

            if (detected) {

                technologies.push(
                    technology
                );

            }

        }

        return technologies;

    }

}