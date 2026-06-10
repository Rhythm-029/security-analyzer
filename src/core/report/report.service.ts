import {
  AnalysisReport,
  RepositoryCoverage,
  RepositoryContext,
  RepositoryFileDescriptor,
  RepositoryGraphSnapshot,
  RiskAssessment,
  SecurityFinding,
} from "../domain/appsec.types";
import { ReportGeneratorContract } from "../contracts/appsec.contracts";

export class ReportService implements ReportGeneratorContract {
  generate(input: {
    repositoryPath: string;
    files: RepositoryFileDescriptor[];
    context: RepositoryContext;
    graph: RepositoryGraphSnapshot;
    findings: SecurityFinding[];
    risk: RiskAssessment;
    recommendations: string[];
    coverage: RepositoryCoverage;
  }): AnalysisReport {
    const repositorySummary = {
      path: input.repositoryPath,
      fileCount: input.files.length,
      sourceFileCount: input.files.filter(file => file.isSource).length,
      manifestCount: input.files.filter(file => file.isManifest).length,
      technologyCount: input.context.technologyStack.length,
      moduleCount: input.context.repositoryModules.length,
      securityModuleCount: input.context.securityModules.length,
      capabilityCount: input.context.capabilities.length,
      serviceCount: input.context.thirdPartyServices.length,
      dataStoreCount: input.context.dataStores.length,
      exposureCount: input.context.exposures.length,
    };

    const recommendations = this.deriveRecommendations(input.findings, input.context, input.recommendations);

    return {
      repository: repositorySummary,
      context: input.context,
      graph: input.graph,
      findings: input.findings,
      risk: input.risk,
      recommendations,
      coverage: input.coverage,
    };
  }

  private deriveRecommendations(findings: SecurityFinding[], context: RepositoryContext, seedRecommendations: string[]): string[] {
    const recommendations = new Set<string>(seedRecommendations);

    if (findings.some(finding => finding.category === "unauthenticated_exposure" || finding.category === "missing_auth")) {
      recommendations.add("Require explicit authentication and authorization for exposed entry points.");
    }

    if (findings.some(finding => finding.category === "unused_dependency")) {
      recommendations.add("Remove unused runtime dependencies to shrink attack surface and simplify supply-chain review.");
    }

    if (findings.some(finding => finding.category === "missing_dependency")) {
      recommendations.add("Align imports with declared manifests to restore dependency integrity.");
    }

    if (context.securityModules.length === 0 && context.capabilities.some(capability => capability.category === "authentication" || capability.category === "authorization")) {
      recommendations.add("Isolate identity and access-control logic into a dedicated security boundary.");
    }

    if (context.dataStores.length > 0) {
      recommendations.add("Review data-store access paths for least privilege, input validation, and secret handling.");
    }

    if (context.thirdPartyServices.length > 0) {
      recommendations.add("Track external service trust boundaries and vendor exposure in policy and inventory.");
    }

    return Array.from(recommendations);
  }
}
