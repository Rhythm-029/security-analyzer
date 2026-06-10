import {
  CapabilityDescriptor,
  DataStoreDescriptor,
  DependencyDescriptor,
  ExposureDescriptor,
  RepositoryEdgeKind,
  RepositoryFileDescriptor,
  RepositoryGraphEdge,
  RepositoryGraphNode,
  RepositoryGraphSnapshot,
  RepositoryNodeKind,
  TechnologyDescriptor,
} from "../domain/appsec.types";
import { RepositoryGraphContract } from "../contracts/appsec.contracts";

export class RepositoryGraphService implements RepositoryGraphContract {
  private readonly nodes = new Map<string, RepositoryGraphNode>();
  private readonly edges = new Map<string, RepositoryGraphEdge>();
  private repositoryNodeId: string | undefined;

  addRepository(repositoryPath: string): string {
    const id = this.nodeId("repository", repositoryPath);
    this.repositoryNodeId = id;
    this.upsertNode({
      id,
      kind: "repository",
      name: repositoryPath,
      path: repositoryPath,
      metadata: { repositoryPath },
    });
    return id;
  }

  addFile(file: RepositoryFileDescriptor): string {
    const id = this.nodeId("file", file.absolutePath);
    this.upsertNode({
      id,
      kind: "file",
      name: file.fileName,
      path: file.absolutePath,
      language: file.language,
      metadata: {
        relativePath: file.relativePath,
        kind: file.kind,
        sizeBytes: file.sizeBytes,
        isBinary: file.isBinary,
        isManifest: file.isManifest,
        isSource: file.isSource,
        isConfiguration: file.isConfiguration,
        isGenerated: file.isGenerated,
      },
    });

    if (this.repositoryNodeId) {
      this.addEdge({
        from: this.repositoryNodeId,
        to: id,
        kind: "contains",
        metadata: { relation: "contains" },
      });
    }

    return id;
  }

  addManifest(file: RepositoryFileDescriptor): string {
    const id = this.nodeId("manifest", file.absolutePath);
    this.upsertNode({
      id,
      kind: "manifest",
      name: file.fileName,
      path: file.absolutePath,
      metadata: {
        relativePath: file.relativePath,
        kind: file.kind,
        language: file.language,
      },
    });
    return id;
  }

  addDependency(dependency: DependencyDescriptor, filePath: string): string {
    const id = this.nodeId("dependency", `${dependency.ecosystem}:${dependency.name}`);
    this.upsertNode({
      id,
      kind: "dependency",
      name: dependency.name,
      path: filePath,
      metadata: {
        ecosystem: dependency.ecosystem,
        version: dependency.version,
        scope: dependency.scope,
        status: dependency.status,
        sourceFile: dependency.sourceFile,
        usedByFiles: dependency.usedByFiles,
      },
    });

    this.addEdge({
      from: filePath,
      to: id,
      kind: "declares",
      metadata: {
        scope: dependency.scope,
        status: dependency.status,
      },
    });

    return id;
  }

  addTechnology(technology: TechnologyDescriptor, filePath: string): string {
    const id = this.nodeId("technology", technology.id);
    this.upsertNode({
      id,
      kind: "technology",
      name: technology.name,
      path: filePath,
      metadata: {
        ecosystem: technology.ecosystem,
        confidence: technology.confidence,
        evidence: technology.evidence,
      },
    });

    this.addEdge({
      from: filePath,
      to: id,
      kind: "references",
      metadata: { reason: "technology" },
    });

    return id;
  }

  addModule(moduleName: string, filePath: string, metadata: Record<string, unknown> = {}): string {
    const id = this.nodeId("module", moduleName);
    this.upsertNode({
      id,
      kind: "module",
      name: moduleName,
      path: filePath,
      metadata,
    });
    return id;
  }

  addService(service: string, filePath: string, metadata: Record<string, unknown> = {}): string {
    const id = this.nodeId("service", service);
    this.upsertNode({
      id,
      kind: "service",
      name: service,
      path: filePath,
      metadata,
    });
    return id;
  }

  addDataStore(store: DataStoreDescriptor, filePath: string): string {
    const id = this.nodeId("datastore", store.id);
    this.upsertNode({
      id,
      kind: "datastore",
      name: store.name,
      path: filePath,
      metadata: {
        kind: store.kind,
        files: store.files,
        evidence: store.evidence,
        confidence: store.confidence,
      },
    });
    return id;
  }

  addCapability(capability: CapabilityDescriptor, filePath: string): string {
    const id = this.nodeId("capability", capability.id);
    this.upsertNode({
      id,
      kind: "capability",
      name: capability.name,
      path: filePath,
      metadata: {
        category: capability.category,
        confidence: capability.confidence,
        evidence: capability.evidence,
        graphEvidence: capability.graphEvidence,
      },
    });

    this.addEdge({
      from: filePath,
      to: id,
      kind: "references",
      metadata: { reason: "capability" },
    });

    return id;
  }

  addExposure(exposure: ExposureDescriptor, filePath: string): string {
    const id = this.nodeId("endpoint", exposure.id);
    this.upsertNode({
      id,
      kind: "endpoint",
      name: exposure.kind,
      path: filePath,
      metadata: {
        route: exposure.route,
        protocol: exposure.protocol,
        authentication: exposure.authentication,
        confidence: exposure.confidence,
        evidence: exposure.evidence,
      },
    });

    this.addEdge({
      from: filePath,
      to: id,
      kind: "exposes",
      metadata: { route: exposure.route, protocol: exposure.protocol },
    });

    return id;
  }

  addEdge(edge: RepositoryGraphEdge): void {
    const key = `${edge.from}|${edge.kind}|${edge.to}`;
    if (this.edges.has(key)) {
      return;
    }

    this.edges.set(key, edge);
  }

  snapshot(): RepositoryGraphSnapshot {
    return {
      nodes: Array.from(this.nodes.values()),
      edges: Array.from(this.edges.values()),
    };
  }

  private upsertNode(node: RepositoryGraphNode): void {
    const existing = this.nodes.get(node.id);
    if (!existing) {
      this.nodes.set(node.id, node);
      return;
    }

    this.nodes.set(node.id, {
      ...existing,
      ...node,
      metadata: {
        ...existing.metadata,
        ...node.metadata,
      },
    });
  }

  private nodeId(kind: RepositoryNodeKind, value: string): string {
    return `${kind}:${value}`;
  }
}
