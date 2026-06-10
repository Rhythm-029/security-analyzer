import { Router, Request, Response } from "express";
import { ScanOrchestratorService } from "../core/orchestrator/scan-orchestrator.service";
import { ScanOptions } from "../core/domain/appsec.types";
import { getDefaultRepositoryPath, normalizeRepositoryPath } from "../config/repository.config";

const router = Router();
const orchestrator = new ScanOrchestratorService();

type ScanRequestBody = {
  repositoryPath?: string;
  includeSemgrep?: boolean;
  includeGeneratedFiles?: boolean;
  maxConcurrency?: number;
  maxFileSizeBytes?: number;
};

function resolveRepositoryPath(req: Request): string | undefined {
  const body = req.body as ScanRequestBody | undefined;
  const queryPath = typeof req.query.repositoryPath === "string" ? req.query.repositoryPath : undefined;
  const rawPath = body?.repositoryPath ?? queryPath ?? getDefaultRepositoryPath();
  return rawPath ? normalizeRepositoryPath(rawPath) : undefined;
}

function resolveOptions(req: Request): ScanOptions {
  const body = req.body as ScanRequestBody | undefined;

  return {
    includeSemgrep: body?.includeSemgrep,
    includeGeneratedFiles: body?.includeGeneratedFiles,
    maxConcurrency: body?.maxConcurrency,
    maxFileSizeBytes: body?.maxFileSizeBytes,
  };
}

async function handleScan(req: Request, res: Response) {
  try {
    const repositoryPath = resolveRepositoryPath(req);
    if (!repositoryPath) {
      return res.status(400).json({
        success: false,
        message: "repositoryPath is required",
      });
    }

    const report = await orchestrator.execute(repositoryPath, resolveOptions(req));

    return res.json({
      success: true,
      report,
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Repository scan failed",
    });
  }
}

router.get("/", handleScan);
router.post("/", handleScan);

export default router;