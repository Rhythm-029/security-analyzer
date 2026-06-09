import { MODULE_SIGNALS } from "../signals/module.signals";

export class KeywordAnalyzer {

    analyze(text: string) {

        const scores: Record<string, number> = {};

        const lowerText = text.toLowerCase();

        for (const [module, config] of Object.entries(MODULE_SIGNALS)) {

            scores[module] = 0;

            for (const keyword of config.keywords) {

                if (lowerText.includes(keyword.toLowerCase())) {

                    scores[module] += 1;

                }

            }

        }

        return scores;

    }

}