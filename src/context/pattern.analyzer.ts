import { MODULE_SIGNALS } from "../signals/module.signals";

export class PatternAnalyzer {

    analyze(text: string) {

        const scores: Record<string, number> = {};

        for (const [module, config] of Object.entries(MODULE_SIGNALS)) {

            scores[module] = 0;

            for (const pattern of config.patterns) {

                if (text.includes(pattern)) {

                    scores[module] += 3;

                }

            }

        }

        return scores;

    }

}