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
    return seedRecommendations;
  }
}
