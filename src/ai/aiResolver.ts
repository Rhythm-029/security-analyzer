import { OllamaProvider }
from "./providers/ollama.provider";

export class AIResolver {

    private provider =
        new OllamaProvider();

    async resolve(
        fileName: string,
        content: string,
        scores: Record<string, number>
    ) {

        return this.provider.classify(
            fileName,
            content,
            scores
        );

    }

}