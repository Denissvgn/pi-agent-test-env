import path from "node:path";
import fs from "node:fs";

function realOrResolved(p) {
  const resolved = path.resolve(p);
  try {
    return fs.realpathSync(resolved);
  } catch {
    return resolved;
  }
}

function within(candidate, root) {
  return candidate === root || candidate.startsWith(root + path.sep);
}

/**
 * Validates that targetPath resolves strictly within workspaceRoot.
 * Performs lexical containment checks and resolves symlinks on existing paths.
 */
export function isWithinWorkspace(targetPath, cwd, workspaceRoot = "/workspace") {
  if (!targetPath || typeof targetPath !== "string") {
    return false;
  }
  const root = path.resolve(workspaceRoot);
  const realRoot = realOrResolved(root);
  const baseDir = cwd ? path.resolve(cwd) : root;
  const resolved = path.resolve(baseDir, targetPath);

  // Lexical path prefix check
  if (!within(resolved, root)) {
    return false;
  }

  // Symlink escape check on existing path components
  try {
    let current = resolved;
    while (current !== "/" && current !== ".") {
      if (fs.existsSync(current)) {
        const real = fs.realpathSync(current);
        if (!within(real, root) && !within(real, realRoot)) {
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
 * True when targetPath lies under the workspace or under tmpDir (the value of
 * the TMPDIR environment variable by default).
 */
export function isWritablePath(targetPath, cwd, workspaceRoot = "/workspace", tmpDir = process.env.TMPDIR) {
  if (isWithinWorkspace(targetPath, cwd, workspaceRoot)) {
    return true;
  }
  if (typeof tmpDir === "string" && path.isAbsolute(tmpDir)) {
    return isWithinWorkspace(targetPath, cwd, tmpDir);
  }
  return false;
}

const WRITE_COMMANDS_ANY_ARG = new Set(["tee", "touch", "rm", "chmod"]);
const WRITE_COMMANDS_TARGET_ARG = new Set(["mv", "cp", "ln", "install"]);

function underOpt(token) {
  return token.startsWith("/opt/");
}

function unquote(token) {
  return token.replace(/^["']+|["']+$/g, "");
}

function simpleCommandWritesOpt(simple) {
  // A redirect with > or >> whose target starts with /opt/.
  if (/(?:^|[^>])>{1,2}\s*["']?\/opt\//.test(simple)) {
    return true;
  }
  const tokens = simple.split(/\s+/).filter(Boolean).map(unquote);
  let i = 0;
  while (i < tokens.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(tokens[i])) i++;
  const name = tokens[i] === undefined ? "" : tokens[i].split("/").pop();
  const args = tokens.slice(i + 1);
  if (WRITE_COMMANDS_ANY_ARG.has(name)) {
    return args.some(underOpt);
  }
  if (WRITE_COMMANDS_TARGET_ARG.has(name)) {
    const positional = [];
    for (let j = 0; j < args.length; j++) {
      const arg = args[j];
      if (arg === "-t" || arg === "--target-directory") {
        if (args[j + 1] !== undefined && underOpt(args[j + 1])) return true;
        j++;
      } else if (arg.startsWith("--target-directory=")) {
        if (underOpt(arg.slice("--target-directory=".length))) return true;
      } else if (!arg.startsWith("-")) {
        positional.push(arg);
      }
    }
    if (positional.length === 0) return false;
    if (underOpt(positional[positional.length - 1])) return true;
    // Moving a path out of /opt removes it there.
    return name === "mv" && positional.some(underOpt);
  }
  return false;
}

/**
 * True when the command writes under /opt: a > or >> redirect, or tee, touch,
 * rm, mv, cp, ln, install or chmod aimed at a /opt/ path, within one simple
 * command (split on ;, &&, || and |). Reading or running /opt paths is allowed.
 * This only improves the message a model sees; the read-only mount is the real
 * boundary.
 */
export function isBlockedCommand(command) {
  if (typeof command !== "string") {
    return false;
  }
  return command.split(/;|&&|\|\||\||\n/).some(simpleCommandWritesOpt);
}

/**
 * Pi Extension: Workspace Boundary Guard.
 * Adds write/edit path checks and a Bash pattern guard. OS mounts provide the
 * filesystem boundary; this is not a general shell parser/confinement proof.
 */
export default function (pi) {
  const WORKSPACE_ROOT = path.resolve("/workspace");

  pi.on("tool_call", (event, ctx) => {
    const cwd = ctx?.cwd || process.cwd() || WORKSPACE_ROOT;

    for (const [tool, label] of [["write", "Write"], ["edit", "Edit"]]) {
      if (event.toolName !== tool) continue;
      const filePath = event.input?.path;
      if (!isWritablePath(filePath, cwd, WORKSPACE_ROOT)) {
        return {
          block: true,
          reason: `Security violation: ${label} operation blocked. Target path "${filePath}" resolves outside the project workspace (${WORKSPACE_ROOT}) and the temporary directory. The Pi agent may write only within the project workspace or under TMPDIR.`,
        };
      }
    }

    // Guard bash tool against writes to the protected /opt mounts
    if (event.toolName === "bash") {
      const cmd = event.input?.command;
      if (isBlockedCommand(cmd)) {
        return {
          block: true,
          reason: `Security violation: Bash command blocked. Attempted to modify protected control directory: ${cmd}`,
        };
      }
    }
  });
}
