import { AnalysisReport, RepositoryFileDescriptor, ScanOptions, SecurityFinding } from "../domain/appsec.types";
import { ContextEngineService } from "../context/context-engine.service";
import { RiskEngineService } from "../risk/risk-engine.service";
import { ReportService } from "../report/report.service";
import { SemgrepService } from "../../semgrep/semgrep.service";

type SemgrepFinding = {
  ruleId: string;
  severity: string;
  file: string;
  line: number;
  message: string;
};

export class ScanOrchestratorService {
  private readonly contextEngine = new ContextEngineService();
  private readonly semgrepService = new SemgrepService();
  private readonly riskEngine = new RiskEngineService();
  private readonly reportService = new ReportService();

  async execute(repositoryPath: string, options?: ScanOptions): Promise<AnalysisReport> {
    const analysis = await this.contextEngine.analyze(repositoryPath, options);
    const semgrepFindings = options?.includeSemgrep === false ? [] : await this.semgrepService.scanRepository(repositoryPath);
    const rawFindings = [
      ...this.normalizeSemgrepFindings(semgrepFindings, analysis.files),
      ...this.buildStructuralFindings(analysis.files, analysis.context),
    ];

    // Deduplicate findings using Rule ID/Category, FilePath, Line
    const uniqueFindings = new Map<string, SecurityFinding>();
    for (const finding of rawFindings) {
      const lineNum = finding.location?.line || 0;
      const fileKey = finding.filePath || "";
      const ruleKey = finding.category || "";
      const dupKey = `${ruleKey}:${fileKey}:${lineNum}`;

      if (!uniqueFindings.has(dupKey)) {
        uniqueFindings.set(dupKey, finding);
      }
    }
    const normalizedFindings = Array.from(uniqueFindings.values());

    const risk = this.riskEngine.assess(normalizedFindings, analysis.context);
    const recommendations = this.buildRecommendations(normalizedFindings, analysis.context);

    return this.reportService.generate({
      repositoryPath,
      files: analysis.files,
      context: analysis.context,
      graph: analysis.graph,
      findings: normalizedFindings,
      risk,
      recommendations,
      coverage: analysis.coverage,
    });
  }

  private normalizeSemgrepFindings(findings: SemgrepFinding[], files: RepositoryFileDescriptor[]): SecurityFinding[] {
    return findings.map((finding, index) => {
      const severity = this.normalizeSeverity(finding.severity);
      const filePath = this.resolveFilePath(finding.file, files);
      return {
        id: `semgrep:${index}:${finding.ruleId}`,
        source: "semgrep",
        category: finding.ruleId,
        severity,
        confidence: 0.85,
        title: finding.ruleId,
        description: finding.message,
        filePath,
        location: filePath ? { filePath, line: finding.line || undefined } : undefined,
        evidence: [finding.ruleId, finding.message],
        reachability: severity === "CRITICAL" ? 90 : severity === "HIGH" ? 70 : severity === "MEDIUM" ? 40 : 20,
        exposure: 40,
        exploitability: severity === "CRITICAL" ? 90 : severity === "HIGH" ? 75 : severity === "MEDIUM" ? 50 : 25,
        criticality: 30,
        businessImpact: 30,
        riskScore: 0,
        classification: "security_finding",
      };
    });
  }

  private buildStructuralFindings(files: RepositoryFileDescriptor[], context: AnalysisReport["context"]): SecurityFinding[] {
    const findings: SecurityFinding[] = [];

    for (const dependency of context.thirdPartyDependencies) {
      if (dependency.scope === "runtime" && dependency.status === "declared_unused") {
        findings.push({
          id: `policy:unused-dependency:${dependency.id}`,
          source: "policy",
          category: "unused_dependency",
          severity: "LOW",
          confidence: 0.9,
          title: `Unused runtime dependency ${dependency.name}`,
          description: `The dependency ${dependency.name} is declared but not referenced by parsed source files.`,
          filePath: dependency.sourceFile,
          evidence: dependency.usedByFiles.length > 0 ? dependency.usedByFiles : [dependency.sourceFile],
          reachability: 10,
          exposure: 5,
          exploitability: 10,
          criticality: 5,
          businessImpact: 10,
          riskScore: 0,
          classification: "hygiene",
        });
      }

      if (dependency.status === "missing") {
        findings.push({
          id: `policy:missing-dependency:${dependency.id}`,
          source: "policy",
          category: "missing_dependency",
          severity: "MEDIUM",
          confidence: 0.85,
          title: `Undeclared dependency usage ${dependency.name}`,
          description: `Source files reference ${dependency.name}, but the manifest does not declare it.`,
          filePath: dependency.sourceFile,
          evidence: dependency.usedByFiles.length > 0 ? dependency.usedByFiles : [dependency.sourceFile],
          reachability: 25,
          exposure: 20,
          exploitability: 20,
          criticality: 15,
          businessImpact: 20,
          riskScore: 0,
          classification: "hygiene",
        });
      }
    }

    for (const exposure of context.exposures) {
      if (exposure.kind === "api" && exposure.authentication !== "required") {
        findings.push({
          id: `graph:unauthenticated-exposure:${exposure.id}`,
          source: "graph",
          category: "unauthenticated_exposure",
          severity: "MEDIUM",
          confidence: exposure.confidence,
          title: `Potential unauthenticated external surface`,
          description: `An exposed API-like entry point was detected without clear authentication evidence.`,
          filePath: exposure.files[0],
          evidence: exposure.evidence,
          reachability: 80,
          exposure: 90,
          exploitability: 70,
          criticality: 65,
          businessImpact: 60,
          riskScore: 0,
          classification: "observation",
        });
      }
    }

    return findings;
  }

  private buildRecommendations(findings: SecurityFinding[], context: AnalysisReport["context"]): string[] {
    const recommendations = new Set<string>();

    const sortedFindings = [...findings].sort((left, right) => {
      const severityWeights = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
      return (severityWeights[right.severity] || 0) - (severityWeights[left.severity] || 0);
    });

    for (const finding of sortedFindings) {
      if (finding.category === "unauthenticated_exposure" || finding.category === "missing_auth") {
        recommendations.add("Require explicit authentication and authorization for exposed entry points.");
      }
      if (finding.category === "unused_dependency") {
        recommendations.add("Remove unused runtime dependencies to shrink attack surface and simplify supply-chain review.");
      }
      if (finding.category === "missing_dependency") {
        recommendations.add("Align imports with declared manifests to restore dependency integrity.");
      }
    }

    if (context.securityModules.length === 0 && context.capabilities.some(c => c.category === "authentication" || c.category === "authorization")) {
      recommendations.add("Isolate identity and access-control logic into a dedicated security boundary.");
    }

    if (context.dataStores.length > 0) {
      recommendations.add("Review data-store access paths for least privilege, input validation, and secret handling.");
    }

    if (context.thirdPartyServices.length > 0) {
      recommendations.add("Track external service trust boundaries and vendor exposure in policy and inventory.");
    }

    if (recommendations.size === 0) {
      recommendations.add("No immediate structural recommendations derived from the current scan.");
    }

    return Array.from(recommendations);
  }

  private normalizeSeverity(severity: string): SecurityFinding["severity"] {
    const upper = severity.toUpperCase();
    if (upper.includes("CRITICAL") || upper === "ERROR") {
      return "CRITICAL";
    }
    if (upper.includes("HIGH") || upper === "WARNING") {
      return "HIGH";
    }
    if (upper.includes("MEDIUM") || upper === "INFO") {
      return "MEDIUM";
    }
    return "LOW";
  }

  private resolveFilePath(candidate: string, files: RepositoryFileDescriptor[]): string | undefined {
    const matched = files.find(file => file.absolutePath.endsWith(candidate) || file.relativePath === candidate || file.fileName === candidate);
    return matched?.absolutePath;
  }
}
