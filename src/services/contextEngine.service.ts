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

import { CapabilityAnalyzer }
from "../context/capability.analyzer";

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

    private capabilityAnalyzer =
    new CapabilityAnalyzer();    

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
                .analyze(
                    fileName,
                    content
                );

                console.log(
    "FILE:",
    fileName
);

console.log(
    "TECH:",
    technologies
);
                if (
    technologies.length > 0
) {

    console.log(
        "Technologies:",
        fileName,
        technologies
    );

}

        let ast = null;

        if (
            fileName.endsWith(".ts") ||
            fileName.endsWith(".js")
        ) {

            try {

                ast =
                    this.astParser
                        .analyze(
                            fileName
                        );

            } catch {

                console.log(
                    `AST failed for ${fileName}`
                );

            }

        }
        const capabilities =
            this.capabilityAnalyzer
                .analyze(ast);

        return {

            fileName,

            role,

            ...result,

            technologies,

            securityAreas,

            ast,

            capabilities,

            scores:
                combinedScores

        };

    }

}