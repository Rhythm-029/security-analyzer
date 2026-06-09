import { Router } from "express";
import { RepositoryScannerService } from "../services/repositoryScanner.service";
import { ContextEngineService } from "../services/contextEngine.service";
import { RepositorySummaryService } from "../services/repoSummary.service";
import { FindingEngine }
from "../security/finding.engine";
import { SemgrepService }
from "../semgrep/semgrep.service";
import { SeverityEngine }
from "../security/severity.engine";
import { SecurityReportService }
from "../report/securityReport.service";

const router = Router();

const scanner = new RepositoryScannerService();
const contextEngine = new ContextEngineService();
const summaryService = new RepositorySummaryService();

const findingEngine =
    new FindingEngine();

const severityEngine =
    new SeverityEngine();
const semgrepService =
    new SemgrepService();
const reportService =
    new SecurityReportService();

router.get("/", async (req, res) => {

    try {

        const files = await scanner.scan(
            "/Users/halfcuptea/Documents/dev/Security-engine/backend"
        );

        console.log(`Scanned ${files.length} files`);
      
        const allFindings = [];
        const results = [];

        for (const file of files) {

    const context =
        await contextEngine.analyzeFile(
            file.absolutePath,
            file.content || ""
        );

    const analyzedFile = {

        path: file.path,
        type: file.type,
        context

    };

    results.push(
        analyzedFile
    );

    const findings =
        findingEngine.analyze(
            analyzedFile
        );

    allFindings.push(
        ...findings
    );

}

const riskScore =
    severityEngine.calculate(
        allFindings
    );
const semgrepFindings =
    await semgrepService
        .scanRepository(
            "/Users/halfcuptea/Documents/dev/Security-engine/backend"
        );

        console.log(
            `Finished analyzing ${results.length} files`
        );

        const repositorySummary =
            summaryService.summarize(
                results
            );
        const report =
    reportService.generate(
        repositorySummary,
        semgrepFindings,
        riskScore
    );

        res.json({

    success: true,

    report

});

    } catch (error) {

        console.error(error);

        res.status(500).json({

            success: false,

            message:
                "Repository scan failed"

        });

    }

});

export default router;