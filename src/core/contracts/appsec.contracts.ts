import {
  AnalysisReport,
  CapabilityDescriptor,
  DataStoreDescriptor,
  DependencyManifestFact,
  DependencyAnalysisResult,
  DependencyDescriptor,
  ExposureDescriptor,
  RepositoryContext,
  RepositoryCoverage,
  RepositoryFileDescriptor,
  RepositoryGraphEdge,
  RepositoryGraphSnapshot,
  RiskAssessment,
  ScanOptions,
  SecurityFinding,
  SourceFactSet,
  TechnologyDescriptor,
} from "../domain/appsec.types";

export interface RepositoryScannerContract {
  scan(repositoryPath: string, options?: ScanOptions): Promise<RepositoryFileDescriptor[]>;
  readText(absolutePath: string): Promise<string>;
}

export interface LanguageAdapterContract {
  readonly id: string;
  supports(file: RepositoryFileDescriptor): boolean;
  parse(file: RepositoryFileDescriptor, content: string): Promise<SourceFactSet>;
}

export interface LanguageRegistryContract {
  resolve(file: RepositoryFileDescriptor): LanguageAdapterContract | undefined;
  register(adapter: LanguageAdapterContract): void;
}

export interface DependencyAnalyzerContract {
  analyze(
    files: RepositoryFileDescriptor[],
    fileContents: Map<string, string>,
    sourceFactsByFile: Map<string, SourceFactSet>,
  ): Promise<DependencyAnalysisResult>;
}

export interface RepositoryGraphContract {
  addRepository(repositoryPath: string): string;
  addFile(file: RepositoryFileDescriptor): string;
  addManifest(file: RepositoryFileDescriptor): string;
  addDependency(dependency: DependencyDescriptor, filePath: string): string;
  addTechnology(technology: TechnologyDescriptor, filePath: string): string;
  addModule(moduleName: string, filePath: string, metadata?: Record<string, unknown>): string;
  addService(service: string, filePath: string, metadata?: Record<string, unknown>): string;
  addDataStore(store: DataStoreDescriptor, filePath: string): string;
  addCapability(capability: CapabilityDescriptor, filePath: string): string;
  addExposure(exposure: ExposureDescriptor, filePath: string): string;
  addEdge(edge: RepositoryGraphEdge): void;
  snapshot(): RepositoryGraphSnapshot;
}

export interface ContextEngineContract {
  analyze(repositoryPath: string, options?: ScanOptions): Promise<{
    files: RepositoryFileDescriptor[];
    coverage: RepositoryCoverage;
    context: RepositoryContext;
    graph: RepositoryGraphSnapshot;
    sourceFactsByFile: Map<string, SourceFactSet>;
    dependencyAnalysis: DependencyAnalysisResult;
  }>;
}

export interface CapabilityAnalyzerContract {
  analyze(params: {
    graph: RepositoryGraphSnapshot;
    sourceFactsByFile: Map<string, SourceFactSet>;
    dependencyFacts: DependencyAnalysisResult;
  }): CapabilityDescriptor[];
}

export interface RiskEngineContract {
  assess(findings: SecurityFinding[], context: RepositoryContext): RiskAssessment;
}

export interface ReportGeneratorContract {
  generate(input: {
    repositoryPath: string;
    files: RepositoryFileDescriptor[];
    context: RepositoryContext;
    graph: RepositoryGraphSnapshot;
    findings: SecurityFinding[];
    risk: RiskAssessment;
    recommendations: string[];
    coverage: RepositoryCoverage;
  }): AnalysisReport;
}
