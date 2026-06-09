import { AIProvider }
from "../interfaces/aiProvider.interface";

export class OllamaProvider
implements AIProvider {

    async classify(
        fileName: string,
        content: string,
        scores: Record<string, number>
    ) {

        return {
            module: "unknown",
            confidence: 50
        };

    }

}