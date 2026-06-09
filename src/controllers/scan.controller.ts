import { Request, Response } from "express";
import { RepositoryScannerService } from "../services/repositoryScanner.service";

const scanner = new RepositoryScannerService();

export const scanRepository = async (
  req: Request,
  res: Response
) => {
  try {
    const { path } = req.body;

    if (!path) {
      return res.status(400).json({
        success: false,
        message: "Repository path is required"
      });
    }

    const files = await scanner.scan(path);

    return res.json({
      success: true,
      totalFiles: files.length,
      files
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      message: "Repository scan failed"
    });
  }
};