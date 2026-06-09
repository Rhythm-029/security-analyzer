export interface AIProvider {

    classify(
        fileName: string,
        content: string,
        scores: Record<string, number>
    ): Promise<any>;

}