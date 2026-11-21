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

/**
 * Splits a command into simple commands (on unquoted ;, &&, ||, | and newline)
 * and words, honouring single quotes, double quotes and backslash escapes.
 * Quoted or escaped text is argument text, never an operator. An unquoted > or
 * >> is a redirect operator; redirectsToOpt records whether its target
 * (optionally quoted) starts with /opt/.
 * Standard redirections are I/O metadata, not operands: an unquoted fd number
 * glued to the operator (2>, 1>>, 0<), the operator itself, its target word,
 * and fd duplications (>&2, 2>&1, <&0, >&-) are kept out of words, so the
 * command's own operands stay identifiable. A quoted digit ("2">f) is an
 * ordinary operand. This is lexical only: no expansion, no process substitution.
 */
function parseSimpleCommands(command) {
  const simples = [];
  let words = [];
  let word = "";
  let inWord = false;
  let redirectsToOpt = false;
  let quote = null;
  let plain = true; // current word has no quoted or escaped part
  let skipWord = false; // next completed word is a redirect target

  const endWord = () => {
    if (inWord) {
      if (skipWord) skipWord = false;
      else words.push(word);
    }
    word = "";
    inWord = false;
    plain = true;
  };
  const endSimple = () => {
    endWord();
    simples.push({ words, redirectsToOpt });
    words = [];
    redirectsToOpt = false;
    skipWord = false;
  };

  for (let i = 0; i < command.length; i++) {
    const ch = command[i];
    if (quote === "'") {
      if (ch === "'") quote = null;
      else word += ch;
    } else if (quote === '"') {
      if (ch === '"') quote = null;
      else if (ch === "\\" && i + 1 < command.length && '"\\$`'.includes(command[i + 1])) word += command[++i];
      else word += ch;
    } else if (ch === "'" || ch === '"') {
      quote = ch;
      inWord = true;
      plain = false;
    } else if (ch === "\\") {
      if (i + 1 < command.length) word += command[++i];
      inWord = true;
      plain = false;
    } else if (ch === ";" || ch === "\n") {
      endSimple();
    } else if (ch === "&" && command[i + 1] === "&") {
      i++;
      endSimple();
    } else if (ch === "|") {
      if (command[i + 1] === "|") i++;
      endSimple();
    } else if (ch === ">" || ch === "<") {
      // An unquoted fd number (or &, as in &>) glued to the operator belongs to it.
      if (inWord && plain && (/^[0-9]+$/.test(word) || (ch === ">" && word === "&"))) {
        word = "";
        inWord = false;
      } else {
        endWord();
      }
      let j = i;
      while (command[j] === ch) j++;
      if (command[j] === "(") {
        // Process substitution is outside this lexer; leave it as ordinary text.
      } else if (command[j] === "&" && /[0-9-]/.test(command[j + 1] ?? "")) {
        // fd duplication or close (>&2, <&0, >&-): no target word.
        j++;
        while (command[j] >= "0" && command[j] <= "9") j++;
        if (command[j] === "-") j++;
      } else {
        if (command[j] === "&") j++; // >&file sends both streams to file
        skipWord = true;
        if (ch === ">") {
          let k = j;
          while (command[k] === " " || command[k] === "\t") k++;
          if (command[k] === '"' || command[k] === "'") k++;
          if (command.startsWith("/opt/", k)) redirectsToOpt = true;
        }
      }
      i = j - 1;
    } else if (ch === " " || ch === "\t") {
      endWord();
    } else {
      word += ch;
      inWord = true;
    }
  }
  endSimple();
  return simples;
}

function simpleCommandWritesOpt({ words: tokens, redirectsToOpt }) {
  // An unquoted > or >> whose target starts with /opt/.
  if (redirectsToOpt) {
    return true;
  }
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
 * command (split on unquoted ;, &&, || and |). Redirect operators and quotes
 * are recognised lexically: a > inside quoted text is not a redirect. Reading
 * or running /opt paths is allowed.
 * This only improves the message a model sees; the read-only mount is the real
 * boundary.
 */
export function isBlockedCommand(command) {
  if (typeof command !== "string") {
    return false;
  }
  return parseSimpleCommands(command).some(simpleCommandWritesOpt);
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
