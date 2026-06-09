export class ConfidenceEngine {

    calculate(scores: Record<string, number>) {

        let highestModule = "unknown";
        let highestScore = 0;

        const totalScore =
            Object.values(scores)
                .reduce(
                    (sum, score) => sum + score,
                    0
                );

        for (
            const [module, score]
            of Object.entries(scores)
        ) {

            if (score > highestScore) {

                highestScore = score;
                highestModule = module;

            }

        }

        const confidence =
            totalScore === 0
                ? 0
                : Math.round(
                    (highestScore / totalScore) * 100
                );

        return {
            module: highestModule,
            confidence
        };

    }

}