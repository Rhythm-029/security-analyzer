import { KeywordAnalyzer }
from "../context/keyword.analyzer";

import { PatternAnalyzer }
from "../context/pattern.analyzer";

import { ConfidenceEngine }
from "../context/confidence.engine";

import { TechnologyAnalyzer }
from "../context/technology.analyzer";

import { SecurityAnalyzer }
from "../context/security.analyzer";

import { ASTParserService }
from "../parser/astParser.service";

import { FileRoleDetector }
from "../context/fileRoleDetector";

export class ContextEngineService {

    private keywordAnalyzer =
        new KeywordAnalyzer();

    private patternAnalyzer =
        new PatternAnalyzer();

    private confidenceEngine =
        new ConfidenceEngine();

    private technologyAnalyzer =
        new TechnologyAnalyzer();
    
    private securityAnalyzer =
    new SecurityAnalyzer();

    private astParser =
    new ASTParserService();

    private fileRoleDetector =
    new FileRoleDetector();

    async analyzeFile(
        fileName: string,
        content: string
    ) {

        const keywordScores =
            this.keywordAnalyzer
                .analyze(content);

        const patternScores =
            this.patternAnalyzer
                .analyze(content);

        const combinedScores:
            Record<string, number> = {};
        
        const securityAreas =
            this.securityAnalyzer
                .analyze(content);
    
        const role =
            this.fileRoleDetector
                .detect(fileName);

        for (
            const module of Object.keys(
                keywordScores
            )
        ) {

            combinedScores[module] =
                (keywordScores[module] || 0)
                +
                (patternScores[module] || 0);

        }

        const result =
            this.confidenceEngine
                .calculate(combinedScores);

        const technologies =
            this.technologyAnalyzer
                .analyze(content);
        let ast = null;
        if (
    fileName.endsWith(".ts") ||
    fileName.endsWith(".js")
) {

    try {

        ast =
            this.astParser
                .analyze(fileName);

    } catch (error) {

        console.log(
            `AST failed for ${fileName}`
        );

    }
     


}
        return {
            fileName,
            role,
            ...result,
            technologies,
            securityAreas,
            ast,
            scores: combinedScores
        };

    }

}