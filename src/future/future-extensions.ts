import { AnalysisReport, SecurityFinding } from "../core/domain/appsec.types";

/**
 * Interface for saving/retrieving scan reports in database storage.
 */
export interface IMongoStorage {
  saveReport(report: AnalysisReport): Promise<boolean>;
  getReportById(id: string): Promise<AnalysisReport | null>;
  listReports(): Promise<AnalysisReport[]>;
}

/**
 * Interface for vector database integrations.
 */
export interface IVectorDb {
  upsertVector(id: string, vector: number[], metadata: Record<string, any>): Promise<boolean>;
  searchSimilar(vector: number[], limit: number): Promise<Array<{ id: string; score: number; metadata: Record<string, any> }>>;
}

/**
 * Interface for generating vector embeddings from text chunks.
 */
export interface IEmbeddings {
  generate(text: string): Promise<number[]>;
  generateBatch(texts: string[]): Promise<number[][]>;
}

/**
 * Interface for offline AI Large Language Model (LLM) security analyses.
 */
export interface IAiAnalyzer {
  explainFinding(finding: SecurityFinding): Promise<{ whyItMatters: string; attackScenario: string; remediation: string }>;
  suggestFixPattern(finding: SecurityFinding): Promise<string>;
}

/**
 * Interface for RAG (Retrieval-Augmented Generation) query retrieval.
 */
export interface IRagRetriever {
  queryContext(query: string, limit: number): Promise<string[]>;
}

/**
 * Interface for interactive repository chat assistant.
 */
export interface IRepositoryChat {
  askQuestion(question: string, context: string[]): Promise<string>;
}

// ---------------------------------------------------------
// Placeholder mock classes demonstrating clean integration
// ---------------------------------------------------------

export class MongoStorageService implements IMongoStorage {
  async saveReport(report: AnalysisReport): Promise<boolean> {
    console.log(`[STORAGE] [MOCK] Saving report for repository: ${report.repository.path} to MongoDB.`);
    return true;
  }
  async getReportById(id: string): Promise<AnalysisReport | null> {
    console.log(`[STORAGE] [MOCK] Fetching report: ${id} from MongoDB.`);
    return null;
  }
  async listReports(): Promise<AnalysisReport[]> {
    return [];
  }
}

export class VectorDbService implements IVectorDb {
  async upsertVector(id: string, vector: number[], metadata: Record<string, any>): Promise<boolean> {
    console.log(`[VECTOR] [MOCK] Upserting embedding vector for id: ${id} (Dimension: ${vector.length}).`);
    return true;
  }
  async searchSimilar(vector: number[], limit: number): Promise<Array<{ id: string; score: number; metadata: Record<string, any> }>> {
    console.log(`[VECTOR] [MOCK] Searching vector similarity (Limit: ${limit}).`);
    return [];
  }
}

export class EmbeddingsService implements IEmbeddings {
  async generate(text: string): Promise<number[]> {
    // Return empty 1536-dimensional float vector placeholder
    return new Array(1536).fill(0);
  }
  async generateBatch(texts: string[]): Promise<number[][]> {
    return texts.map(() => new Array(1536).fill(0));
  }
}

export class AiAnalyzerService implements IAiAnalyzer {
  async explainFinding(finding: SecurityFinding): Promise<{ whyItMatters: string; attackScenario: string; remediation: string }> {
    return {
      whyItMatters: "Mock explanations: Explains the vulnerability in business terms.",
      attackScenario: "Mock attack scenario: Shows how an attacker would leverage this finding.",
      remediation: "Mock remediation: Explains general steps to secure."
    };
  }
  async suggestFixPattern(finding: SecurityFinding): Promise<string> {
    return "// Suggested fix placeholder";
  }
}

export class RagRetrieverService implements IRagRetriever {
  async queryContext(query: string, limit: number): Promise<string[]> {
    console.log(`[RAG] [MOCK] Retrieving similarity context for query: "${query}" (limit ${limit}).`);
    return [];
  }
}

export class RepositoryChatService implements IRepositoryChat {
  async askQuestion(question: string, context: string[]): Promise<string> {
    return `[CHAT] [MOCK] Answer based on ${context.length} retrieved files for question: "${question}".`;
  }
}
