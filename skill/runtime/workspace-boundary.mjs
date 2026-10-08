import path from "node:path";
import fs from "node:fs";

/**
 * Validates that targetPath resolves strictly within workspaceRoot.
 * Performs lexical containment checks and resolves symlinks on existing paths.
 */
export function isWithinWorkspace(targetPath, cwd, workspaceRoot = "/workspace") {
  if (!targetPath || typeof targetPath !== "string") {
    return false;
  }
  const root = path.resolve(workspaceRoot);
  const baseDir = cwd ? path.resolve(cwd) : root;
  const resolved = path.resolve(baseDir, targetPath);

  // Lexical path prefix check
  if (!resolved.startsWith(root + path.sep) && resolved !== root) {
    return false;
  }

  // Symlink escape check on existing path components
  try {
    let current = resolved;
    while (current !== "/" && current !== ".") {
      if (fs.existsSync(current)) {
        const real = fs.realpathSync(current);
        if (!real.startsWith(root + path.sep) && real !== root) {
          return false;
        }
        break;
      }
      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }
  } catch {
    // If realpath resolution fails, lexical check still holds
  }

  return true;
}

/**
 * Pi Extension: Workspace Boundary Guard.
 * Adds write/edit path checks and a Bash pattern guard. OS mounts provide the
 * filesystem boundary; this regex is not a general shell parser/confinement proof.
 */
export default function (pi) {
  const WORKSPACE_ROOT = path.resolve("/workspace");

  pi.on("tool_call", (event, ctx) => {
    const cwd = ctx?.cwd || process.cwd() || WORKSPACE_ROOT;

    // Guard write tool
    if (event.toolName === "write") {
      const filePath = event.input?.path;
      if (!isWithinWorkspace(filePath, cwd, WORKSPACE_ROOT)) {
        return {
          block: true,
          reason: `Security violation: Write operation blocked. Target path "${filePath}" resolves outside the project workspace (${WORKSPACE_ROOT}). The Pi agent is strictly restricted to write within the project workspace.`,
        };
      }
      const baseDir = cwd ? path.resolve(cwd) : WORKSPACE_ROOT;
      const resolved = path.resolve(baseDir, filePath);
      if (resolved.startsWith(path.resolve(WORKSPACE_ROOT, ".pi-runtime/inbox"))) {
        return {
          block: true,
          reason: `Security violation: Write operation blocked. Target path "${filePath}" resolves to protected control inbox.`,
        };
      }
    }

    // Guard edit tool
    if (event.toolName === "edit") {
      const filePath = event.input?.path;
      if (!isWithinWorkspace(filePath, cwd, WORKSPACE_ROOT)) {
        return {
          block: true,
          reason: `Security violation: Edit operation blocked. Target path "${filePath}" resolves outside the project workspace (${WORKSPACE_ROOT}). The Pi agent is strictly restricted to write within the project workspace.`,
        };
      }
      const baseDir = cwd ? path.resolve(cwd) : WORKSPACE_ROOT;
      const resolved = path.resolve(baseDir, filePath);
      if (resolved.startsWith(path.resolve(WORKSPACE_ROOT, ".pi-runtime/inbox"))) {
        return {
          block: true,
          reason: `Security violation: Edit operation blocked. Target path "${filePath}" resolves to protected control inbox.`,
        };
      }
    }

    // Guard bash tool against targeting protected mounts outside /workspace or protected inbox
    if (event.toolName === "bash") {
      const cmd = event.input?.command;
      if (typeof cmd === "string") {
        if (/(?:>|>>|tee\s+|touch\s+|rm\s+|mv\s+|cp\s+.*)\s*(?:\/opt\b|.*\.pi-runtime\/inbox)/.test(cmd)) {
          return {
            block: true,
            reason: `Security violation: Bash command blocked. Attempted to modify protected control directory: ${cmd}`,
          };
        }
      }
    }
  });
}
