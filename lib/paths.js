import fs from "node:fs";
import path from "node:path";
import { expandHome } from "./util.js";

export function canonicalizePath(rawPath, opts = {}) {
  if (typeof rawPath !== "string") return "";
  const expanded = expandHome(rawPath.trim());
  if (!expanded) return "";

  let normalized = path.normalize(expanded);
  if (!path.isAbsolute(normalized)) {
    if (opts.baseDir && typeof opts.baseDir === "string") {
      normalized = path.resolve(opts.baseDir, normalized);
    } else {
      return normalized;
    }
  }

  try {
    return fs.realpathSync.native(normalized);
  } catch {
    return normalized;
  }
}

export function isInsideDirectory(filePath, directory) {
  if (!filePath || !directory) return false;
  if (filePath === directory) return true;
  const rel = path.relative(directory, filePath);
  return !!rel && !rel.startsWith("..") && !path.isAbsolute(rel);
}

export function nearestExistingAncestorRealpath(filePath) {
  let current = path.resolve(filePath);
  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) return null;
    current = parent;
  }
  try {
    return fs.realpathSync.native(current);
  } catch {
    return null;
  }
}

export function workspaceTrusted(filePath, prefixes = [], opts = {}) {
  const normalized = canonicalizePath(filePath, opts);
  return prefixes.some((prefix) => isInsideDirectory(normalized, prefix));
}
