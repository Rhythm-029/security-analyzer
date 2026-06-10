export type FileKind =
  | "source"
  | "manifest"
  | "config"
  | "documentation"
  | "binary"
  | "generated"
  | "unknown";

export type SourceLanguage = string;

export type DependencyScope =
  | "runtime"
  | "dev"
  | "peer"
  | "optional"
  | "transitive";

export type DependencyStatus =
  | "declared_used"
  | "declared_unused"
  | "missing"
  | "transitive";

export type RiskSeverity =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export type TechnologyEcosystem = string;

export type CapabilityCategory =
  | "authentication"
  | "authorization"
  | "crypto"
  | "secret_management"
  | "data_access"
  | "external_service"
  | "network_exposure"
  | "message_processing"
  | "configuration"
  | "identity"
  | "other";

export type ExposureKind =
  | "api"
  | "webhook"
  | "grpc"
  | "message_queue"
  | "cron"
  | "admin_surface"
  | "public_asset"
  | "internal_service"
  | "unknown";

export type DataStoreKind =
  | "sql"
  | "nosql"
  | "kv"
  | "search"
  | "queue"
  | "blob"
  | "cache"
  | "filesystem"
  | "unknown";

export interface SourceLocation {
  filePath: string;
  line?: number;
  column?: number;
}

export interface RepositoryFileDescriptor {
  absolutePath: string;
  relativePath: string;
  fileName: string;
  extension: string;
  kind: FileKind;
  language?: SourceLanguage;
  sizeBytes: number;
  isBinary: boolean;
  isManifest: boolean;
  isSource: boolean;
  isConfiguration: boolean;
  isGenerated: boolean;
}

export interface SourceSymbolFact {
  name: string;
  kind: "class" | "function" | "interface" | "method" | "variable" | "export";
}

export interface SourceFactSet {
  imports: string[];
  functionCalls: string[];
  envReferences: string[];
  routes: RouteFact[];
  declarations: SourceSymbolFact[];
  exports: string[];
}

export interface RouteFact {
  framework: string;
  method: string;
  path: string;
  middleware: string[];
  authenticationHint: "unknown" | "required" | "none";
}

export interface TechnologyDescriptor {
  id: string;
  name: string;
  ecosystem: TechnologyEcosystem;
  confidence: number;
  evidence: string[];
  files: string[];
}

export interface DependencyDescriptor {
  id: string;
  name: string;
  version?: string;
  ecosystem: TechnologyEcosystem;
  scope: DependencyScope;
  status: DependencyStatus;
  sourceFile: string;
  usedByFiles: string[];
  evidence: string[];
}

export interface DependencyManifestFact {
  ecosystem: TechnologyEcosystem;
  manifestFile: string;
  declaredDependencies: DependencyDescriptor[];
  devDependencies: DependencyDescriptor[];
  peerDependencies: DependencyDescriptor[];
  optionalDependencies: DependencyDescriptor[];
  lockfileDependencies: DependencyDescriptor[];
}

export interface DependencyAnalysisResult {
  manifests: DependencyManifestFact[];
  dependencies: DependencyDescriptor[];
}

export interface ModuleDescriptor {
  id: string;
  name: string;
  kind: "application" | "service" | "package" | "library" | "boundary" | "module" | "component";
  files: string[];
  imports: string[];
  exports: string[];
  confidence: number;
  evidence: string[];
}

export interface SecurityModuleDescriptor {
  id: string;
  name: string;
  category:
    | "authentication"
    | "authorization"
    | "crypto"
    | "secret_management"
    | "input_validation"
    | "access_control"
    | "session_management"
    | "policy"
    | "other";
  files: string[];
  evidence: string[];
  confidence: number;
}

export interface ExternalServiceDescriptor {
  id: string;
  name: string;
  category:
    | "identity"
    | "payment"
    | "storage"
    | "messaging"
    | "email"
    | "analytics"
    | "logging"
    | "feature_flag"
    | "ai"
    | "unknown";
  endpoints: string[];
  files: string[];
  evidence: string[];
  confidence: number;
}

export interface DataStoreDescriptor {
  id: string;
  name: string;
  kind: DataStoreKind;
  files: string[];
  evidence: string[];
  confidence: number;
}

export interface CapabilityDescriptor {
  id: string;
  name: string;
  category: CapabilityCategory;
  confidence: number;
  evidence: string[];
  graphEvidence: string[];
}

export interface ExposureDescriptor {
  id: string;
  kind: ExposureKind;
  route?: string;
  protocol?: string;
  authentication: "unknown" | "none" | "required";
  files: string[];
  evidence: string[];
  confidence: number;
}

export interface RepositoryContext {
  technologyStack: TechnologyDescriptor[];
  thirdPartyDependencies: DependencyDescriptor[];
  thirdPartyServices: ExternalServiceDescriptor[];
  repositoryModules: ModuleDescriptor[];
  securityModules: SecurityModuleDescriptor[];
  capabilities: CapabilityDescriptor[];
  exposures: ExposureDescriptor[];
  dataStores: DataStoreDescriptor[];
}

export type RepositoryNodeKind =
  | "repository"
  | "file"
  | "manifest"
  | "module"
  | "symbol"
  | "dependency"
  | "service"
  | "endpoint"
  | "datastore"
  | "capability"
  | "finding"
  | "technology";

export type RepositoryEdgeKind =
  | "contains"
  | "imports"
  | "calls"
  | "declares"
  | "depends_on"
  | "uses_service"
  | "exposes"
  | "reads_from"
  | "writes_to"
  | "belongs_to"
  | "resolves_to"
  | "references";

export interface RepositoryGraphNode {
  id: string;
  kind: RepositoryNodeKind;
  name: string;
  path?: string;
  language?: SourceLanguage;
  metadata: Record<string, unknown>;
}

export interface RepositoryGraphEdge {
  from: string;
  to: string;
  kind: RepositoryEdgeKind;
  weight?: number;
  metadata: Record<string, unknown>;
}

export interface RepositoryGraphSnapshot {
  nodes: RepositoryGraphNode[];
  edges: RepositoryGraphEdge[];
}

export interface SecurityFinding {
  id: string;
  source: "semgrep" | "graph" | "policy";
  category: string;
  severity: RiskSeverity;
  confidence: number;
  title: string;
  description: string;
  filePath?: string;
  location?: SourceLocation;
  evidence: string[];
  reachability: number;
  exposure: number;
  exploitability: number;
  criticality: number;
  businessImpact: number;
  riskScore: number;
}

export interface RiskFactors {
  severity: number;
  reachability: number;
  exposure: number;
  exploitability: number;
  criticality: number;
  businessImpact: number;
  confidence: number;
}

export interface RiskAssessment {
  score: number;
  level: RiskSeverity;
  factors: RiskFactors;
}

export interface RepositoryCoverage {
  parsedFiles: number;
  sourceFiles: number;
  manifestFiles: number;
  configurationFiles: number;
  unsupportedFiles: number;
  binaryFiles: number;
}

export interface RepositorySummary {
  path: string;
  fileCount: number;
  sourceFileCount: number;
  manifestCount: number;
  technologyCount: number;
  moduleCount: number;
  securityModuleCount: number;
  capabilityCount: number;
  serviceCount: number;
  dataStoreCount: number;
  exposureCount: number;
}

export interface AnalysisReport {
  repository: RepositorySummary;
  context: RepositoryContext;
  graph: RepositoryGraphSnapshot;
  findings: SecurityFinding[];
  risk: RiskAssessment;
  recommendations: string[];
  coverage: RepositoryCoverage;
}

export interface ScanOptions {
  includeSemgrep?: boolean;
  includeGeneratedFiles?: boolean;
  maxConcurrency?: number;
  maxFileSizeBytes?: number;
}
