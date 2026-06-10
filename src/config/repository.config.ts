import path from "path";
import { fileURLToPath } from "url";

export function normalizeRepositoryPath(input: string): string {
  const raw = input.trim();

  if (!raw) {
    return "";
  }

  const unquoted = raw.replace(/^['"]|['"]$/g, "");
  const expanded = unquoted.startsWith("~/")
    ? path.join(process.env.HOME || "", unquoted.slice(2))
    : unquoted;

  if (expanded.startsWith("file://")) {
    return path.normalize(fileURLToPath(expanded));
  }

  const percentDecoded = safeDecodeURIComponent(expanded).replace(/\\ /g, " ");
  const absoluteOrRelative = percentDecoded.startsWith("/") || /^[A-Za-z]:[\\/]/.test(percentDecoded)
    ? percentDecoded
    : path.resolve(percentDecoded);

  return path.normalize(absoluteOrRelative);
}

export function getDefaultRepositoryPath(): string {
  return normalizeRepositoryPath(process.env.REPOSITORY_PATH?.trim() || "");
}

function safeDecodeURIComponent(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}
