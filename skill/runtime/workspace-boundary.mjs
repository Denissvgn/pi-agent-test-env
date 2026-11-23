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

/** Directories the Bash guard protects. */
const PROTECTED_ROOTS = ["/opt"];

function underProtected(p) {
  return PROTECTED_ROOTS.some((root) => p === root || p.startsWith(root + "/"));
}

function isProtectedAncestor(p) {
  return PROTECTED_ROOTS.some((root) => root.startsWith(p === "/" ? "/" : p + "/"));
}

/**
 * True when targetPath lies under the workspace or under tmpDir (the value of
 * the TMPDIR environment variable by default). A tmpDir of "/" or one inside a
 * protected root is ignored.
 */
export function isWritablePath(targetPath, cwd, workspaceRoot = "/workspace", tmpDir = process.env.TMPDIR) {
  if (isWithinWorkspace(targetPath, cwd, workspaceRoot)) {
    return true;
  }
  if (typeof tmpDir === "string" && path.isAbsolute(tmpDir)) {
    const tmp = realOrResolved(tmpDir);
    if (tmp === "/" || underProtected(tmp) || underProtected(path.resolve(tmpDir))) {
      return false;
    }
    return isWithinWorkspace(targetPath, cwd, tmpDir);
  }
  return false;
}

// ---------------------------------------------------------------------------
// Bash guard: a lexer for the shell subset an agent writes, and an analysis of
// each simple command for writes under a protected root.
// ---------------------------------------------------------------------------

const UNKNOWN = "\u0001"; // stands for an expansion whose value is not known
const MAX_DEPTH = 12;
const MAX_CANDIDATES = 1024;

class ShellParseError extends Error {}

function newCommand(start) {
  return { words: [], redirs: [], subs: [], op: "", start, end: start, raw: "" };
}

/**
 * Splits shell source into simple commands. Command boundaries are the
 * unquoted operators ; & | && || |& ;; ;& ;;& ( ) and newline. Words keep
 * their quoting (parts with q=true), so quoted text is never an operator.
 * $( ), backticks, <( ) and >( ) are parsed recursively and attached to the
 * enclosing command as `subs`; ${...} and $NAME are kept as variable parts;
 * here-document bodies are attached to their redirection. Unbalanced quotes or
 * substitutions raise ShellParseError.
 */
class ShellParser {
  constructor(src) {
    this.s = src;
    this.i = 0;
    this.pending = []; // here-documents waiting for the next newline
  }

  parseList(terminator) {
    const s = this.s;
    const cmds = [];
    let cur = newCommand(this.i);
    let depth = 0;
    let caseDepth = 0; // inside case ... esac a ")" ends a pattern, not $( )
    const finish = (op) => {
      cur.op = op;
      cur.raw = s.slice(cur.start, this.i);
      cmds.push(cur);
      cur = newCommand(this.i);
    };
    for (;;) {
      if (this.i >= s.length) {
        if (terminator) throw new ShellParseError("unterminated substitution");
        this.readHeredocs();
        finish("");
        return cmds;
      }
      const ch = s[this.i];
      if (ch === " " || ch === "\t" || ch === "\r") { this.i++; continue; }
      if (ch === "\\" && s[this.i + 1] === "\n") { this.i += 2; continue; }
      if (ch === "#") { while (this.i < s.length && s[this.i] !== "\n") this.i++; continue; }
      if (ch === "\n") { this.i++; finish("\n"); this.readHeredocs(); continue; }
      if (ch === ")") {
        if (depth === 0 && terminator === ")" && caseDepth === 0) { finish(""); this.i++; return cmds; }
        if (depth > 0) depth--;
        this.i++; finish(")"); continue;
      }
      if (ch === "(") { depth++; this.i++; finish("("); continue; }
      if (ch === "&" && s[this.i + 1] === ">") { this.parseRedirect(cur, null); continue; }
      const op = [";;&", ";;", ";&", ";", "&&", "||", "|&", "|", "&"].find((o) => s.startsWith(o, this.i));
      if (op) { this.i += op.length; finish(op); continue; }
      if ((ch === "<" || ch === ">") && s[this.i + 1] !== "(") { this.parseRedirect(cur, null); continue; }
      const word = this.parseWord(cur.subs);
      const next = s[this.i];
      if ((next === "<" || next === ">") && s[this.i + 1] !== "(" && isFdWord(word)) {
        this.parseRedirect(cur, word);
        continue;
      }
      if (cur.words.length === 0 && !word.quoted) {
        if (word.raw === "case") caseDepth++;
        else if (word.raw === "esac" && caseDepth > 0) caseDepth--;
      }
      cur.words.push(word);
    }
  }

  parseWord(subs, stopAtBrace = false) {
    const s = this.s;
    const parts = [];
    const start = this.i;
    let quoted = false;
    const lit = (text, q) => {
      const last = parts[parts.length - 1];
      if (last && last.t === "lit" && last.q === q) last.s += text;
      else parts.push({ t: "lit", s: text, q });
    };
    let braceDepth = 0;
    while (this.i < s.length) {
      const ch = s[this.i];
      if (stopAtBrace) {
        if (ch === "}" && braceDepth === 0) break;
        if (ch === "{") braceDepth++;
        if (ch === "}") braceDepth--;
      } else if (" \t\r\n;&|()<>".includes(ch)) {
        if ((ch === "<" || ch === ">") && s[this.i + 1] === "(" ) {
          // process substitution <( ) or >( )
          this.i += 2;
          subs.push(this.parseList(")"));
          parts.push({ t: "unk", q: false });
          continue;
        }
        break;
      }
      if (ch === "'") {
        const end = s.indexOf("'", this.i + 1);
        if (end < 0) throw new ShellParseError("unterminated single quote");
        lit(s.slice(this.i + 1, end), true);
        this.i = end + 1;
        quoted = true;
      } else if (ch === '"') {
        this.i++;
        this.parseDoubleQuoted(parts, subs);
        quoted = true;
      } else if (ch === "\\") {
        if (s[this.i + 1] === "\n") { this.i += 2; continue; }
        if (this.i + 1 < s.length) lit(s[this.i + 1], true);
        this.i += 2;
        quoted = true;
      } else if (ch === "$" && s[this.i + 1] === "'") {
        this.i += 2;
        lit(this.parseAnsiC(), true);
        quoted = true;
      } else if (ch === "$" && s[this.i + 1] === '"') {
        this.i += 2;
        this.parseDoubleQuoted(parts, subs);
        quoted = true;
      } else if (ch === "$") {
        parts.push(this.parseDollar(subs, false));
      } else if (ch === "`") {
        parts.push(this.parseBacktick(subs, false));
      } else if (ch === "~" && this.i === start && !stopAtBrace) {
        let j = this.i + 1;
        while (j < s.length && /[A-Za-z0-9_.-]/.test(s[j])) j++;
        parts.push({ t: "tilde", user: s.slice(this.i + 1, j), q: false });
        this.i = j;
      } else {
        lit(ch, false);
        this.i++;
      }
    }
    return { parts, quoted, raw: s.slice(start, this.i) };
  }

  parseDoubleQuoted(parts, subs) {
    const s = this.s;
    let text = "";
    const flush = () => { if (text) { parts.push({ t: "lit", s: text, q: true }); text = ""; } };
    while (this.i < s.length) {
      const ch = s[this.i];
      if (ch === '"') { this.i++; flush(); return; }
      if (ch === "\\" && this.i + 1 < s.length && '$`"\\\n'.includes(s[this.i + 1])) {
        if (s[this.i + 1] !== "\n") text += s[this.i + 1];
        this.i += 2;
      } else if (ch === "$" && /[A-Za-z_{(0-9?!@*#$-]/.test(s[this.i + 1] ?? "")) {
        flush();
        parts.push(this.parseDollar(subs, true));
      } else if (ch === "`") {
        flush();
        parts.push(this.parseBacktick(subs, true));
      } else {
        text += ch;
        this.i++;
      }
    }
    throw new ShellParseError("unterminated double quote");
  }

  parseAnsiC() {
    const s = this.s;
    let out = "";
    const map = { n: "\n", t: "\t", r: "\r", a: "\x07", b: "\b", e: "\x1b", E: "\x1b", f: "\f", v: "\v", "\\": "\\", "'": "'", '"': '"', "?": "?" };
    while (this.i < s.length) {
      const ch = s[this.i];
      if (ch === "'") { this.i++; return out; }
      if (ch === "\\" && this.i + 1 < s.length) {
        const n = s[this.i + 1];
        let m;
        if (map[n] !== undefined) { out += map[n]; this.i += 2; }
        else if ((m = /^x([0-9a-fA-F]{1,2})/.exec(s.slice(this.i + 1)))) { out += String.fromCharCode(parseInt(m[1], 16)); this.i += 1 + m[0].length; }
        else if ((m = /^[uU]([0-9a-fA-F]{1,8})/.exec(s.slice(this.i + 1)))) { out += String.fromCodePoint(Math.min(parseInt(m[1], 16), 0x10ffff)); this.i += 1 + m[0].length; }
        else if ((m = /^[0-7]{1,3}/.exec(s.slice(this.i + 1)))) { out += String.fromCharCode(parseInt(m[0], 8)); this.i += 1 + m[0].length; }
        else { out += "\\" + n; this.i += 2; }
      } else {
        out += ch;
        this.i++;
      }
    }
    throw new ShellParseError("unterminated $' quote");
  }

  parseDollar(subs, q) {
    const s = this.s;
    const next = s[this.i + 1];
    if (next === "(") {
      if (s[this.i + 2] === "(") {
        // Arithmetic $(( )): scan to the matching parenthesis, then parse the
        // inside so nested substitutions are still examined.
        let j = this.i + 3;
        let depth = 2;
        while (j < s.length && depth > 0) {
          if (s[j] === "(") depth++;
          else if (s[j] === ")") depth--;
          j++;
        }
        if (depth > 0) throw new ShellParseError("unterminated arithmetic");
        const inner = s.slice(this.i + 3, j - 2);
        this.i = j;
        subs.push(new ShellParser(inner).parseList(null));
        return { t: "unk", q };
      }
      this.i += 2;
      subs.push(this.parseList(")"));
      return { t: "unk", q };
    }
    if (next === "{") {
      this.i += 2;
      let m = /^(#?)([A-Za-z_][A-Za-z0-9_]*|[0-9]+|[?!@*#$-])/.exec(s.slice(this.i));
      if (!m) {
        // Unusual form: keep scanning to the closing brace and treat as unknown.
        this.parseWord(subs, true);
        if (s[this.i] !== "}") throw new ShellParseError("unterminated ${");
        this.i++;
        return { t: "unk", q };
      }
      this.i += m[0].length;
      const lengthOf = m[1] === "#";
      const name = m[2];
      const opm = /^(:-|:=|:\+|:\?|-|=|\+|\?|##|#|%%|%|\/\/|\/|\^\^|\^|,,|,|:|\[|@)?/.exec(s.slice(this.i));
      const op = opm[1] || "";
      this.i += op.length;
      const arg = this.parseWord(subs, true);
      if (s[this.i] !== "}") throw new ShellParseError("unterminated ${");
      this.i++;
      if (lengthOf) return { t: "unk", q };
      return { t: "var", name, op, arg, q };
    }
    const m = /^([A-Za-z_][A-Za-z0-9_]*|[0-9?!@*#$-])/.exec(s.slice(this.i + 1));
    if (m) {
      this.i += 1 + m[0].length;
      if (/^[A-Za-z_]/.test(m[0])) return { t: "var", name: m[0], op: "", arg: null, q };
      return { t: "unk", q };
    }
    this.i++;
    return { t: "lit", s: "$", q };
  }

  parseBacktick(subs, q) {
    const s = this.s;
    let j = this.i + 1;
    let inner = "";
    while (j < s.length && s[j] !== "`") {
      if (s[j] === "\\" && j + 1 < s.length && "$`\\".includes(s[j + 1])) { inner += s[j + 1]; j += 2; }
      else { inner += s[j]; j++; }
    }
    if (j >= s.length) throw new ShellParseError("unterminated backtick");
    this.i = j + 1;
    subs.push(new ShellParser(inner).parseList(null));
    return { t: "unk", q };
  }

  parseRedirect(cmd, fdWord) {
    const s = this.s;
    const ops = ["&>>", "&>", ">>", ">|", ">&", ">", "<<<", "<<-", "<<", "<>", "<&", "<"];
    const op = ops.find((o) => s.startsWith(o, this.i));
    this.i += op.length;
    while (s[this.i] === " " || s[this.i] === "\t") this.i++;
    if (this.i >= s.length || " \t\r\n;&|()<>".includes(s[this.i])) {
      throw new ShellParseError(`missing redirection target after ${op}`);
    }
    const target = this.parseWord(cmd.subs);
    const redir = { op, fd: fdWord ? wordLiteral(fdWord) : null, target, heredoc: null, dup: false };
    if ((op === ">&" || op === "<&") && !target.quoted && /^([0-9]+-?|-)$/.test(wordLiteral(target))) {
      redir.dup = true;
    }
    if (op === "<<" || op === "<<-") {
      this.pending.push({ redir, cmd, delim: wordLiteral(target), quoted: target.quoted, strip: op === "<<-" });
    }
    cmd.redirs.push(redir);
  }

  readHeredocs() {
    const s = this.s;
    while (this.pending.length) {
      const h = this.pending.shift();
      let body = "";
      while (this.i < s.length) {
        let end = s.indexOf("\n", this.i);
        if (end < 0) end = s.length;
        const line = s.slice(this.i, end);
        this.i = Math.min(end + 1, s.length);
        if ((h.strip ? line.replace(/^\t+/, "") : line) === h.delim) break;
        body += line + "\n";
      }
      h.redir.heredoc = { body, quoted: h.quoted };
      if (!h.quoted) {
        // Unquoted bodies undergo expansion: examine their substitutions.
        const p = new ShellParser(body);
        while (p.i < body.length) {
          const ch = body[p.i];
          if (ch === "\\") p.i += 2;
          else if (ch === "$") p.parseDollar(h.cmd.subs, true);
          else if (ch === "`") p.parseBacktick(h.cmd.subs, true);
          else p.i++;
        }
      }
    }
  }
}

function wordLiteral(word) {
  return word.parts.map((p) => (p.t === "lit" ? p.s : p.t === "tilde" ? "~" + p.user : "$")).join("");
}

function isFdWord(word) {
  if (word.quoted || !word.parts.every((p) => p.t === "lit")) return false;
  const text = wordLiteral(word);
  return /^[0-9]+$/.test(text) || /^\{[A-Za-z_][A-Za-z0-9_]*\}$/.test(text);
}

function parseShell(src) {
  return new ShellParser(src).parseList(null);
}

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

function normalizePath(p) {
  const n = path.posix.normalize(p.replace(/\/+/g, "/"));
  return n.length > 1 && n.endsWith("/") ? n.slice(0, -1) : n;
}

function resolveAgainst(p, cwd) {
  if (p.startsWith("/")) return normalizePath(p);
  if (cwd === null) return null;
  return normalizePath(cwd + "/" + p);
}

/** realpath of the longest existing ancestor, with the remainder appended. */
function realpathPrefix(abs) {
  let head = abs;
  let tail = "";
  for (;;) {
    try {
      const real = fs.realpathSync(head);
      return normalizePath(tail ? real + "/" + tail : real);
    } catch {
      if (head === "/") return abs;
      tail = tail ? path.posix.basename(head) + "/" + tail : path.posix.basename(head);
      head = path.posix.dirname(head);
    }
  }
}

function braceExpand(word) {
  const out = [];
  const visit = (s) => {
    if (out.length > MAX_CANDIDATES) return;
    for (let open = s.indexOf("{"); open >= 0; open = s.indexOf("{", open + 1)) {
      let depth = 0;
      const commas = [];
      let close = -1;
      for (let j = open; j < s.length; j++) {
        if (s[j] === "{") depth++;
        else if (s[j] === "}") { depth--; if (depth === 0) { close = j; break; } }
        else if (s[j] === "," && depth === 1) commas.push(j);
      }
      if (close < 0) break;
      if (commas.length === 0) continue;
      const bounds = [open, ...commas, close];
      for (let k = 0; k + 1 < bounds.length; k++) {
        visit(s.slice(0, open) + s.slice(bounds[k] + 1, bounds[k + 1]) + s.slice(close + 1));
      }
      return;
    }
    out.push(s);
  };
  visit(word);
  // Too many alternatives to check: fail closed.
  if (out.length > MAX_CANDIDATES) out.push(PROTECTED_ROOTS[0]);
  return out;
}

function hasGlob(s) {
  return /[*?[]/.test(s);
}

function globToRegExp(pattern) {
  let re = "";
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "*") re += ".*";
    else if (c === "?") re += ".";
    else if (c === "[") {
      const close = pattern.indexOf("]", i + 2);
      if (close < 0) { re += "\\["; continue; }
      let cls = pattern.slice(i + 1, close);
      if (cls.startsWith("!")) cls = "^" + cls.slice(1);
      re += "[" + cls.replace(/\\/g, "\\\\") + "]";
      i = close;
    } else re += c.replace(/[.+^${}()|\\/]/g, "\\$&");
  }
  try {
    return new RegExp("^" + re + "$", "s");
  } catch {
    return /^.*$/s;
  }
}

function globMayHitProtected(abs, ancestorOk) {
  const comps = abs.split("/").filter(Boolean);
  for (const root of PROTECTED_ROOTS) {
    const rc = root.split("/").filter(Boolean);
    const n = Math.min(comps.length, rc.length);
    let match = true;
    for (let k = 0; k < n; k++) if (!globToRegExp(comps[k]).test(rc[k])) { match = false; break; }
    if (match && (comps.length >= rc.length || ancestorOk)) return true;
  }
  // Expand against the filesystem to catch symlinks into a protected root.
  let bases = ["/"];
  let count = 0;
  for (const comp of comps) {
    const next = [];
    for (const base of bases) {
      if (hasGlob(comp)) {
        let entries = [];
        try { entries = fs.readdirSync(base); } catch { entries = []; }
        const re = globToRegExp(comp);
        for (const e of entries) if (re.test(e)) next.push(path.posix.join(base, e));
      } else {
        next.push(path.posix.join(base, comp));
      }
      count += next.length;
      if (count > 4096) return true;
    }
    bases = next;
  }
  return bases.some((b) => underProtected(realpathPrefix(b)));
}

/**
 * True when the shell word p (already expanded) names a protected path, or with
 * ancestorOk an ancestor of one, after brace expansion, ~ and cwd resolution,
 * slash collapsing, . and .. resolution, glob matching and symlink resolution
 * of the existing prefix. A path whose value depends on an unknown expansion is
 * protected only when its known directory prefix already is.
 */
function isProtectedPath(p, cwd, ancestorOk = false) {
  if (typeof p !== "string" || p === "") return false;
  if (p.includes(UNKNOWN)) {
    const prefix = p.slice(0, p.indexOf(UNKNOWN));
    const dir = prefix.includes("/") ? prefix.slice(0, prefix.lastIndexOf("/") + 1) : "";
    const abs = dir === "" ? cwd : resolveAgainst(dir, cwd);
    if (abs === null) return false;
    return underProtected(abs) || underProtected(realpathPrefix(abs));
  }
  for (const candidate of braceExpand(p)) {
    const abs = resolveAgainst(candidate, cwd);
    if (abs === null) continue;
    if (hasGlob(abs)) {
      if (globMayHitProtected(abs, ancestorOk)) return true;
      continue;
    }
    if (underProtected(abs) || (ancestorOk && isProtectedAncestor(abs))) return true;
    const real = realpathPrefix(abs);
    if (underProtected(real) || (ancestorOk && isProtectedAncestor(real))) return true;
  }
  return false;
}

/** True when free text (inline code, a pipeline) mentions a protected absolute path. */
function mentionsProtected(text) {
  if (typeof text !== "string") return false;
  const tokens = text.match(/(?<![A-Za-z0-9_.~$}\-])\/[^\s'"`;,(){}<>|&=\\*?[\]]*/g) || [];
  return tokens.some((t) => isProtectedPath(t, "/"));
}

// ---------------------------------------------------------------------------
// Expansion
// ---------------------------------------------------------------------------

function lookupVar(part, st, ctx) {
  const name = part.name;
  const base = st.vars.has(name) ? st.vars.get(name) : ctx.env[name];
  const set = base !== undefined;
  const nonEmpty = set && base !== "";
  const argValue = () => (part.arg ? expandString(part.arg, st, ctx) : "");
  switch (part.op) {
    case "": return set ? base : UNKNOWN;
    case ":-": return nonEmpty ? base : argValue();
    case "-": return set ? base : argValue();
    case ":=": if (nonEmpty) return base; st.vars.set(name, argValue()); return st.vars.get(name);
    case "=": if (set) return base; st.vars.set(name, argValue()); return st.vars.get(name);
    case ":+": return nonEmpty ? argValue() : "";
    case "+": return set ? argValue() : "";
    case ":?": case "?": return set ? base : UNKNOWN;
    default: return UNKNOWN;
  }
}

function partValue(part, st, ctx) {
  if (part.t === "lit") return part.s;
  if (part.t === "tilde") {
    if (part.user) return UNKNOWN;
    return ctx.env.HOME ?? UNKNOWN;
  }
  if (part.t === "var") return lookupVar(part, st, ctx);
  return UNKNOWN;
}

function expandString(word, st, ctx) {
  return word.parts.map((p) => partValue(p, st, ctx)).join("");
}

/** Expands a word into fields: unquoted expansions split on blanks. */
function expandFields(word, st, ctx) {
  const fields = [""];
  for (const part of word.parts) {
    const v = partValue(part, st, ctx);
    if (part.t === "var" && !part.q) {
      const pieces = v.split(/[ \t\n]+/);
      fields[fields.length - 1] += pieces[0];
      for (const piece of pieces.slice(1)) fields.push(piece);
    } else {
      fields[fields.length - 1] += v;
    }
  }
  const out = fields.filter((f, k) => f !== "" || (word.quoted && k === 0));
  return out;
}

// ---------------------------------------------------------------------------
// Command analysis
// ---------------------------------------------------------------------------

const RESERVED = new Set(["!", "{", "}", "if", "then", "else", "elif", "fi", "do", "done", "while", "until", "coproc", "esac"]);
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*\+?=/;

// Any non-option operand (and any glued option value) is a write target.
const WRITE_ANY_OPERAND = new Set([
  "rm", "rmdir", "unlink", "touch", "chmod", "chown", "chgrp", "truncate", "shred", "mkdir", "mkfifo", "mknod",
  "tee", "ln", "link", "mv", "setfacl", "chattr", "sudoedit", "mktemp", "fallocate", "sponge",
]);
const RECURSIVE_CAPABLE = new Set(["rm", "chmod", "chown", "chgrp", "setfacl", "chattr"]);
const COMPRESSORS = new Set(["gzip", "gunzip", "bzip2", "bunzip2", "xz", "unxz", "lzma", "zstd", "unzstd", "lz4", "compress"]);
const SHELLS = new Set(["sh", "bash", "zsh", "dash", "ksh", "ash", "mksh", "yash", "rbash", "fish"]);
const DECLARATIONS = new Set(["export", "declare", "typeset", "local", "readonly"]);

// Commands that may run in a protected working directory: they do not write
// files except through a redirection, which is checked separately.
const READ_ONLY = new Set([
  "ls", "cat", "head", "tail", "grep", "egrep", "fgrep", "rg", "wc", "stat", "file", "diff", "cmp",
  "sha1sum", "sha224sum", "sha256sum", "sha384sum", "sha512sum", "md5sum", "b2sum", "cksum", "sum",
  "echo", "printf", "pwd", "cd", "pushd", "popd", "dirs", "test", "[", "true", "false", ":", "readlink",
  "realpath", "basename", "dirname", "tree", "du", "df", "less", "more", "od", "xxd", "hexdump", "strings",
  "cut", "tr", "column", "nl", "id", "whoami", "date", "sleep", "type", "which", "hash", "jq", "find",
  "comm", "paste", "fold", "fmt", "expand", "unexpand", "rev", "tac", "seq", "yes", "printenv", "uname",
  "exit", "return", "set", "shopt", "unset", "wait", "read", "getopts", "shift", "trap",
]);

const WRAPPERS = {
  env: { arg: "uCS", long: ["unset", "chdir", "split-string"], chdir: ["C", "chdir"] },
  command: { arg: "" },
  builtin: { arg: "" },
  exec: { arg: "a" },
  nice: { arg: "n", long: ["adjustment"] },
  nohup: { arg: "" },
  time: { arg: "fo", long: ["format", "output"], outputs: ["o", "output"] },
  timeout: { arg: "sk", long: ["signal", "kill-after"], skip: 1 },
  sudo: { arg: "ugpCDrtTUhR", long: ["user", "group", "prompt", "close-from", "chdir", "role", "type", "other-user", "host"], chdir: ["D", "chdir"] },
  doas: { arg: "uC" },
  stdbuf: { arg: "ioe", long: ["input", "output", "error"] },
  ionice: { arg: "cn", long: ["class", "classdata"] },
  chrt: { arg: "", skip: 1 },
  taskset: { arg: "", skip: 1 },
  setsid: { arg: "" },
  nocache: { arg: "" },
  unbuffer: { arg: "" },
  catchsegv: { arg: "" },
  busybox: { arg: "" },
  flock: { arg: "Ewc", long: ["conflict-exit-code", "timeout", "wait", "command"] },
  xargs: { arg: "aEdILnPs", long: ["arg-file", "delimiter", "max-args", "max-procs", "max-chars", "max-lines", "replace", "eof"] },
  watch: { arg: "nd", long: ["interval", "differences"] },
  su: { arg: "cgGs", long: ["command", "group", "supp-group", "shell"] },
};

/**
 * Generic option scan. spec.arg lists short options that take a value (glued
 * or as the next word); spec.long lists long options that take one. With
 * stop=true scanning ends at the first operand, which is returned with the
 * remaining words in `rest`.
 */
function scanOptions(args, spec, stop = false) {
  const opts = [];
  const pos = [];
  const longArg = new Set(spec.long || []);
  let i = 0;
  for (; i < args.length; i++) {
    const a = args[i];
    if (a === "--") { i++; break; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq < 0 ? a.slice(2) : a.slice(2, eq);
      let val = eq < 0 ? undefined : a.slice(eq + 1);
      if (val === undefined && longArg.has(name)) val = args[++i];
      opts.push({ name, val });
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      for (let k = 1; k < a.length; k++) {
        const c = a[k];
        if ((spec.arg || "").includes(c)) {
          let val = a.slice(k + 1);
          if (val === "") val = args[++i];
          opts.push({ name: c, val });
          break;
        }
        opts.push({ name: c, val: undefined });
      }
      continue;
    }
    if (stop) break;
    pos.push(a);
  }
  if (stop) return { opts, rest: args.slice(i) };
  pos.push(...args.slice(i));
  return { opts, pos };
}

function optValues(opts, names) {
  return opts.filter((o) => names.includes(o.name) && o.val !== undefined).map((o) => o.val);
}

function hasOpt(opts, names) {
  return opts.some((o) => names.includes(o.name));
}

function cloneState(st) {
  return { cwd: st.cwd, oldpwd: st.oldpwd, stack: [...st.stack], vars: new Map(st.vars) };
}

function analyzeScript(text, st, ctx) {
  if (ctx.depth > MAX_DEPTH) return true;
  let cmds;
  try {
    cmds = parseShell(text);
  } catch (err) {
    if (!(err instanceof ShellParseError)) throw err;
    // The shell would reject this too; refuse it when it mentions a protected path.
    return mentionsProtected(text);
  }
  return analyzeList(cmds, st, { ...ctx, depth: ctx.depth + 1 });
}

function analyzeList(cmds, st, ctx) {
  if (ctx.depth > MAX_DEPTH) return true;
  return cmds.some((cmd) => analyzeCommand(cmd, st, ctx));
}

const WRITE_REDIRECTS = new Set([">", ">>", ">|", "&>", "&>>", "<>", ">&"]);

function analyzeCommand(cmd, st, ctx) {
  const inner = { ...ctx, depth: ctx.depth + 1 };
  // Substitutions run in a subshell that starts from the current state.
  for (const sub of cmd.subs) if (analyzeList(sub, cloneState(st), inner)) return true;

  let k = 0;
  while (k < cmd.words.length) {
    const w = cmd.words[k];
    if (!w.quoted && w.parts.length === 1 && w.parts[0].t === "lit" && RESERVED.has(w.parts[0].s)) { k++; continue; }
    break;
  }
  // Leading assignments.
  while (k < cmd.words.length) {
    const w = cmd.words[k];
    const first = w.parts[0];
    if (!first || first.t !== "lit" || first.q) break;
    const m = ASSIGNMENT.exec(first.s);
    if (!m) break;
    const name = m[0].replace(/\+?=$/, "");
    const valueWord = { parts: [{ ...first, s: first.s.slice(m[0].length) }, ...w.parts.slice(1)], quoted: w.quoted };
    st.vars.set(name, expandString(valueWord, st, ctx));
    k++;
  }

  for (const r of cmd.redirs) {
    if (!WRITE_REDIRECTS.has(r.op) || r.dup) continue;
    if (isProtectedPath(expandString(r.target, st, ctx), st.cwd)) return true;
  }

  const argv = [];
  for (const w of cmd.words.slice(k)) argv.push(...expandFields(w, st, ctx));
  return analyzeArgv(argv, cmd, st, ctx, {});
}

function stdinScriptBlocked(cmd, st, ctx, check) {
  for (const r of cmd.redirs) {
    if (r.heredoc) return check(r.heredoc.body);
    if (r.op === "<<<") return check(expandString(r.target, st, ctx));
  }
  if (cmd.redirs.some((r) => r.op === "<")) return false; // a script file: not inspected
  // Fed from a pipe: refuse when the command line mentions a protected path.
  return ctx.mentions;
}

const WRITEISH_CODE = /\bopen\s*\([^)]*,\s*['"]?[rbt]*[wax+]|[>]|\b(write\w*|append\w*|remove|unlink\w*|rmtree|rmdir\w*|rm\w*|rename\w*|replace|mkdir\w*|makedirs|touch|copy\w*|cp\w*|move|chmod\w*|chown\w*|truncate\w*|system|popen|Popen|subprocess|spawn\w*|exec\w*|symlink\w*|link\w*|utime\w*|syswrite|sysopen|tee|create\w*)\b/;

function codeBlocked(code) {
  return mentionsProtected(code) && WRITEISH_CODE.test(code);
}

const INTERPRETERS = [
  { match: /^(python[0-9.]*|pypy[0-9.]*)$/, code: "c", arg: "WXQ", stop: "m", long: [] },
  { match: /^(node|nodejs|bun|deno)$/, code: "ep", arg: "r", stop: "", long: ["eval", "print"], longArg: ["require", "import", "loader", "experimental-loader", "conditions"] },
  { match: /^perl[0-9.]*$/, code: "eE", arg: "Ix", glued: "Mml0", inplace: "i", stop: "", long: [] },
  { match: /^ruby[0-9.]*$/, code: "e", arg: "IrCEFx", inplace: "i", stop: "", long: [] },
  { match: /^php[0-9.]*$/, code: "r", arg: "cdf", stop: "", long: [] },
  { match: /^(lua[0-9.]*|luajit)$/, code: "e", arg: "l", stop: "", long: [] },
];

function analyzeInterpreter(spec, args, cmd, st, ctx) {
  const codes = [];
  let inplace = false;
  let script = null;
  let module = false;
  let stdin = false;
  let files = [];
  const longCode = new Set(spec.long || []);
  const longArg = new Set(spec.longArg || []);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-") { stdin = true; break; }
    if (a === "--") { files = args.slice(i + 1); if (!codes.length) script = files.shift() ?? null; break; }
    if (a.startsWith("--")) {
      const eq = a.indexOf("=");
      const name = eq < 0 ? a.slice(2) : a.slice(2, eq);
      const val = eq < 0 ? undefined : a.slice(eq + 1);
      if (longCode.has(name)) codes.push(val ?? args[++i] ?? "");
      else if (longArg.has(name) && val === undefined) i++;
      continue;
    }
    if (a.startsWith("-") && a.length > 1) {
      let done = false;
      for (let k = 1; k < a.length; k++) {
        const c = a[k];
        if (spec.code.includes(c)) { codes.push(a.slice(k + 1) || (args[++i] ?? "")); break; }
        if (spec.inplace === c) { inplace = true; break; }
        if (spec.stop && spec.stop.includes(c)) { module = true; done = true; break; }
        if (spec.arg.includes(c)) { if (a.slice(k + 1) === "") i++; break; }
        if ((spec.glued || "").includes(c)) break;
      }
      if (done) break;
      continue;
    }
    if (codes.length) files = args.slice(i);
    else { script = a; files = args.slice(i + 1); }
    break;
  }
  if (codes.some(codeBlocked)) return true;
  if (inplace && files.some((f) => isProtectedPath(f, st.cwd))) return true;
  if (!codes.length && !module && (script === null || stdin)) {
    return stdinScriptBlocked(cmd, st, ctx, codeBlocked);
  }
  return false;
}

function analyzeArgv(argv, cmd, st, ctx, flags) {
  while (argv.length && RESERVED.has(argv[0])) argv = argv.slice(1);
  while (argv.length && ASSIGNMENT.test(argv[0])) {
    const eq = argv[0].indexOf("=");
    st.vars.set(argv[0].slice(0, eq).replace(/\+$/, ""), argv[0].slice(eq + 1));
    argv = argv.slice(1);
  }
  if (!argv.length) return false;
  const first = argv[0];
  const args = argv.slice(1);
  if (first === "for" || first === "select") {
    // for NAME in WORDS: NAME takes each word; keep a protected one if present.
    const name = args[0];
    if (name && /^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
      const words = args[1] === "in" ? args.slice(2) : [];
      st.vars.set(name, words.find((w) => isProtectedPath(w, st.cwd)) ?? words[0] ?? UNKNOWN);
    }
    return false;
  }
  if (first === "case" || first === "[[" || first === "function" || first === "time" && args.length === 0) return false;

  const name = first.includes("/") ? first.slice(first.lastIndexOf("/") + 1) : first;
  const cwdProtected = st.cwd !== null && isProtectedPath(st.cwd, "/");

  // Wrappers: skip the wrapper and its options, then examine the real command.
  if (Object.hasOwn(WRAPPERS, name)) {
    const spec = WRAPPERS[name];
    const { opts, rest: r0 } = scanOptions(args, spec, true);
    let rest = r0;
    let st2 = st;
    for (const out of optValues(opts, spec.outputs || [])) if (isProtectedPath(out, st.cwd)) return true;
    const chdir = optValues(opts, spec.chdir || []);
    if (chdir.length) {
      st2 = cloneState(st);
      st2.cwd = resolveAgainst(chdir[chdir.length - 1], st.cwd);
    }
    if (name === "env") {
      if (st2 === st) st2 = cloneState(st);
      while (rest.length && ASSIGNMENT.test(rest[0])) {
        const eq = rest[0].indexOf("=");
        st2.vars.set(rest[0].slice(0, eq), rest[0].slice(eq + 1));
        rest = rest.slice(1);
      }
      for (const split of optValues(opts, ["S", "split-string"])) {
        let words = [];
        try {
          const parsed = parseShell(split);
          words = parsed.flatMap((c) => c.words.flatMap((w) => expandFields(w, st2, ctx)));
        } catch (err) {
          if (!(err instanceof ShellParseError)) throw err;
          return mentionsProtected(split);
        }
        rest = [...words, ...rest];
      }
    }
    if (name === "sudo" && hasOpt(opts, ["e", "edit"])) return rest.some((f) => isProtectedPath(f, st.cwd));
    if (name === "su" || (name === "flock" && hasOpt(opts, ["c", "command"]))) {
      for (const script of optValues(opts, ["c", "command"])) if (analyzeScript(script, cloneState(st2), ctx)) return true;
      if (name === "su") return false;
    }
    if (name === "flock") {
      if (rest.length && isProtectedPath(rest[0], st.cwd)) return true; // the lock file is created
      rest = rest.slice(1);
    }
    if (name === "watch") return rest.length ? analyzeScript(rest.join(" "), cloneState(st2), ctx) : false;
    if (spec.skip) rest = rest.slice(spec.skip);
    if (name === "xargs") {
      if (!rest.length) return false;
      return analyzeArgv(rest, cmd, st2, ctx, { ...flags, unknownArgs: true });
    }
    return analyzeArgv(rest, cmd, st2, ctx, flags);
  }

  if (name === "cd" || name === "pushd") {
    const positional = args.filter((a) => !/^-[LPe@]+$/.test(a));
    const target = positional[0];
    let next;
    if (target === undefined) next = ctx.env.HOME ? normalizePath(ctx.env.HOME) : null;
    else if (target === "-") next = st.oldpwd;
    else if (target.includes(UNKNOWN)) next = mentionsProtected(cmd.raw) ? PROTECTED_ROOTS[0] : null;
    else next = resolveAgainst(target, st.cwd);
    if (name === "pushd") st.stack.push(st.cwd);
    st.oldpwd = st.cwd;
    st.cwd = next;
    return false;
  }
  if (name === "popd") {
    st.oldpwd = st.cwd;
    st.cwd = st.stack.length ? st.stack.pop() : null;
    return false;
  }

  // In a protected working directory only read-only commands may run.
  if (cwdProtected && !READ_ONLY.has(name)) return true;

  // The command name comes from an unknown expansion ($(...), an unset
  // variable): refuse it when any operand names a protected path.
  if (name.includes(UNKNOWN)) return args.some((a) => isProtectedPath(a, st.cwd));

  // A command fed unknown operands (xargs) that writes, in a command line that
  // mentions a protected path.
  if (flags.unknownArgs && !READ_ONLY.has(name) && ctx.mentions) return true;

  if (DECLARATIONS.has(name)) {
    for (const a of args) {
      if (!ASSIGNMENT.test(a)) continue;
      const eq = a.indexOf("=");
      st.vars.set(a.slice(0, eq).replace(/\+$/, ""), a.slice(eq + 1));
    }
    return false;
  }
  if (name === "eval") return analyzeScript(args.join(" "), st, ctx);
  if (name === "trap") {
    const script = args.find((a) => !a.startsWith("-"));
    return script !== undefined ? analyzeScript(script, cloneState(st), ctx) : false;
  }

  if (SHELLS.has(name)) {
    const pre = [];
    for (let i = 0; i < args.length; i++) {
      // +o NAME / -o NAME take a value; rewrite + options so the scan sees them.
      pre.push(args[i].startsWith("+") && args[i].length > 1 ? "-" + args[i].slice(1) : args[i]);
    }
    const { opts, pos } = scanOptions(pre, { arg: "oO", long: ["rcfile", "init-file", "init-command"] });
    if (hasOpt(opts, ["c", "command"])) {
      const longCmd = optValues(opts, ["command"]);
      const script = longCmd.length ? longCmd[0] : pos[0];
      return script === undefined ? false : analyzeScript(script, cloneState(st), ctx);
    }
    if (pos.length && !hasOpt(opts, ["s"])) return false; // script file: not inspected
    return stdinScriptBlocked(cmd, st, ctx, (body) => analyzeScript(body, cloneState(st), ctx));
  }

  for (const spec of INTERPRETERS) {
    if (spec.match.test(name)) return analyzeInterpreter(spec, args, cmd, st, ctx);
  }

  const cwd = st.cwd;
  const prot = (p, anc = false) => isProtectedPath(p, cwd, anc);

  // Running a command in a protected directory via its own -C / --chdir option.
  if (!READ_ONLY.has(name)) {
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if ((a === "-C" || a === "--chdir" || a === "--directory" || a === "--work-tree" || a === "--git-dir") && prot(args[i + 1] ?? "")) return true;
      const m = /^(?:--chdir|--directory|--work-tree|--git-dir)=(.*)$/.exec(a);
      if (m && prot(m[1])) return true;
    }
  }

  if (WRITE_ANY_OPERAND.has(name) || (COMPRESSORS.has(name) && !args.some((a) => /^-[a-zA-Z]*[ckltL]/.test(a) || ["--stdout", "--keep", "--test", "--list"].includes(a)))) {
    const recursive = RECURSIVE_CAPABLE.has(name) && args.some((a) => a === "--recursive" || /^-[a-zA-Z]*[rR]/.test(a));
    let endOfOptions = false;
    for (const a of args) {
      if (!endOfOptions && a === "--") { endOfOptions = true; continue; }
      if (!endOfOptions && a.startsWith("--")) {
        const eq = a.indexOf("=");
        if (eq >= 0 && prot(a.slice(eq + 1), recursive)) return true;
        continue;
      }
      if (!endOfOptions && a.startsWith("-") && a.length > 1) {
        const slash = a.indexOf("/");
        if (slash >= 0 && prot(a.slice(slash), recursive)) return true; // glued value
        continue;
      }
      if (prot(a, recursive)) return true;
    }
    return false;
  }

  if (name === "cp" || name === "install" || name === "scp" || name === "rsync") {
    const specs = {
      cp: { arg: "tS", long: ["target-directory", "suffix"] },
      install: { arg: "gmoSt", long: ["group", "mode", "owner", "suffix", "target-directory"] },
      scp: { arg: "cFiJloPSD" },
      rsync: { arg: "eBfMT", long: ["rsh", "filter", "exclude", "include", "temp-dir", "partial-dir", "backup-dir", "log-file", "files-from", "exclude-from", "include-from", "compare-dest", "copy-dest", "link-dest"] },
    };
    const { opts, pos } = scanOptions(args, specs[name]);
    const targetDirs = name === "cp" || name === "install" ? optValues(opts, ["t", "target-directory"]) : [];
    if (targetDirs.some((v) => prot(v))) return true;
    if (name === "rsync" && optValues(opts, ["T", "temp-dir", "partial-dir", "backup-dir", "log-file"]).some((v) => prot(v))) return true;
    if (name === "install" && hasOpt(opts, ["d", "directory"])) return pos.some((p) => prot(p));
    if (name === "rsync" && hasOpt(opts, ["remove-source-files"])) return pos.some((p) => prot(p));
    if (targetDirs.length) return false; // with -t DIR every operand is a source
    return pos.length > 0 && prot(pos[pos.length - 1]);
  }

  if (name === "dd") return args.some((a) => a.startsWith("of=") && prot(a.slice(3)));

  if (name === "find") {
    let i = 0;
    while (i < args.length && /^-[HLPD]$|^-O\d$/.test(args[i])) i++;
    const starts = [];
    while (i < args.length && !args[i].startsWith("-") && args[i] !== "(" && args[i] !== "!") starts.push(args[i++]);
    if (!starts.length) starts.push(".");
    const expr = args.slice(i);
    // {} stands for every visited path; a start at "/" visits the protected roots.
    const visited = starts.map((s) => {
      const abs = resolveAgainst(s, cwd);
      return abs !== null && isProtectedAncestor(abs) ? PROTECTED_ROOTS[0] : s;
    });
    for (let j = 0; j < expr.length; j++) {
      const e = expr[j];
      if (e === "-delete" && starts.some((s) => prot(s, true))) return true;
      if (["-fprint", "-fprint0", "-fprintf", "-fls"].includes(e) && prot(expr[j + 1] ?? "")) return true;
      if (["-exec", "-execdir", "-ok", "-okdir"].includes(e)) {
        const sub = [];
        for (j++; j < expr.length && expr[j] !== ";" && expr[j] !== "+"; j++) sub.push(expr[j]);
        for (const v of visited) {
          const replaced = sub.map((a) => a.split("{}").join(v));
          if (analyzeArgv(replaced, { ...cmd, redirs: [] }, cloneState(st), ctx, flags)) return true;
        }
      }
    }
    return false;
  }

  if (name === "sed" || name === "gsed") {
    let inplace = false;
    const scripts = [];
    const positional = [];
    for (let i = 0; i < args.length; i++) {
      const a = args[i];
      if (a.startsWith("--in-place")) { inplace = true; continue; }
      if (a === "--expression" || a === "--file") { scripts.push(args[++i] ?? ""); continue; }
      if (a.startsWith("--expression=")) { scripts.push(a.slice(13)); continue; }
      if (a.startsWith("--")) continue;
      if (a.startsWith("-") && a.length > 1) {
        for (let k = 1; k < a.length; k++) {
          const c = a[k];
          if (c === "i") { inplace = true; break; }
          if (c === "e" || c === "f") { scripts.push(a.slice(k + 1) || (args[++i] ?? "")); break; }
          if (c === "l") { if (a.slice(k + 1) === "") i++; break; }
        }
        continue;
      }
      positional.push(a);
    }
    if (!scripts.length && positional.length) scripts.push(positional.shift());
    if (inplace && positional.some((p) => prot(p))) return true;
    return scripts.some((sc) => mentionsProtected(sc) && /[wWe]/.test(sc));
  }

  if (/^(g|m|n)?awk$/.test(name)) {
    const { opts, pos } = scanOptions(args, { arg: "FvfilE", long: ["field-separator", "assign", "file", "include", "load", "exec"] });
    const inplace = optValues(opts, ["i", "include", "l", "load"]).includes("inplace");
    const program = hasOpt(opts, ["f", "file", "E", "exec"]) ? null : pos.shift();
    if (inplace && pos.some((p) => prot(p))) return true;
    return program != null && mentionsProtected(program) && /[>|]|system|getline/.test(program);
  }

  if (name === "tar" || name === "bsdtar" || name === "gtar") {
    const a2 = args.length && /^[A-Za-z]+$/.test(args[0]) ? ["-" + args[0], ...args.slice(1)] : args;
    const { opts } = scanOptions(a2, { arg: "fCbTXgKNVHI", long: ["file", "directory", "files-from", "exclude-from", "listed-incremental", "newer", "volno-file", "use-compress-program", "to-command"] });
    const extract = hasOpt(opts, ["x", "extract", "get"]);
    const writesArchive = hasOpt(opts, ["c", "create", "r", "append", "u", "update", "A", "catenate", "concatenate", "delete"]);
    if (extract && optValues(opts, ["C", "directory"]).some((d) => prot(d))) return true;
    if (writesArchive && optValues(opts, ["f", "file"]).some((f) => prot(f))) return true;
    if (optValues(opts, ["to-command", "use-compress-program", "I"]).some((c) => analyzeScript(c, cloneState(st), ctx))) return true;
    return false;
  }

  if (name === "unzip") {
    const i = args.indexOf("-d");
    return i >= 0 && prot(args[i + 1] ?? "");
  }
  if (name === "patch") {
    const { opts, pos } = scanOptions(args, { arg: "dioDrBpFVYzg", long: ["directory", "input", "output", "reject-file"] });
    if (optValues(opts, ["d", "directory", "o", "output", "r", "reject-file"]).some((v) => prot(v))) return true;
    return pos.length > 0 && prot(pos[0]);
  }
  if (name === "sort") {
    const { opts } = scanOptions(args, { arg: "ktToS", long: ["key", "field-separator", "temporary-directory", "output", "buffer-size"] });
    return optValues(opts, ["o", "output"]).some((v) => prot(v));
  }
  if (name === "uniq") {
    const { pos } = scanOptions(args, { arg: "fsw", long: ["skip-fields", "skip-chars", "check-chars"] });
    return pos.length > 1 && prot(pos[1]);
  }
  if (name === "split" || name === "csplit") {
    const { pos } = scanOptions(args, { arg: "abClnf", long: ["prefix", "suffix-length", "bytes", "line-bytes", "lines", "number"] });
    return pos.slice(1).some((p) => prot(p));
  }
  if (name === "curl" || name === "wget") {
    const spec = name === "curl"
      ? { arg: "oDcKuXHdTFAeEwmxy", long: ["output", "output-dir", "dump-header", "cookie-jar", "trace", "trace-ascii", "stderr", "config"] }
      : { arg: "OPoaeUt", long: ["output-document", "directory-prefix", "output-file", "append-output"] };
    const { opts } = scanOptions(args, spec);
    const names = name === "curl"
      ? ["o", "output", "output-dir", "D", "dump-header", "c", "cookie-jar", "trace", "trace-ascii", "stderr"]
      : ["O", "output-document", "P", "directory-prefix", "o", "output-file", "a", "append-output"];
    return optValues(opts, names).some((v) => prot(v));
  }
  return false;
}

/**
 * True when the Bash command would write under a protected root (/opt).
 *
 * The command is lexed (quotes, escapes, ANSI-C quoting, $( ), backticks,
 * <( ) >( ), ${...}, here-documents) into simple commands separated by any
 * unquoted ; & | && || |& ( ) newline or ;; operator; reserved words (if, then,
 * do, else, elif, !, {, }, ...) and wrapper commands (env, command, exec, nice,
 * nohup, time, timeout, sudo, xargs, flock, stdbuf, ...) with their options are
 * skipped to find the real command. Shell -c strings, eval, trap, here-documents
 * fed to a shell and find -exec commands are analysed recursively. Paths are
 * expanded (known variables, ~, braces, globs) and normalised (repeated slashes,
 * . and .., symlinks of existing prefixes) before comparison, and the working
 * directory is tracked through cd, pushd and popd: in a protected directory
 * only read-only commands may run.
 *
 * Reading or running files under /opt (cat /opt/x, python3 /opt/pi-lab/v.py)
 * stays allowed, and quoted text such as "a > /opt/b" is not a redirection.
 * When the command cannot be lexed it is refused if it mentions a protected
 * path. This is a lexical check, not confinement: a program the agent runs can
 * still write wherever the mounts allow.
 */
export function isBlockedCommand(command, cwd = "/workspace", env = process.env) {
  if (typeof command !== "string") {
    return false;
  }
  const st = { cwd: cwd ? normalizePath(path.resolve(cwd)) : "/workspace", oldpwd: null, stack: [], vars: new Map() };
  const ctx = { depth: 0, env: env || {}, mentions: mentionsProtected(command) };
  return analyzeScript(command, st, ctx);
}

/**
 * Pi Extension: Workspace Boundary Guard.
 * Write/edit tool calls may target only the project workspace or TMPDIR. Bash
 * commands are refused when isBlockedCommand finds a write under /opt.
 *
 * /opt/pi-lab and /opt/pi-control are read-only mounts, so for them this guard
 * only gives the model a clearer message. /opt/pi-control/outbox is mounted
 * writable, so for the outbox this guard is the only check inside the
 * container. It is a lexical check, not a confinement proof: programs the agent
 * runs (a script file, a compiled tool) can still write any writable mount.
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
      if (isBlockedCommand(cmd, cwd)) {
        return {
          block: true,
          reason: `Security violation: Bash command blocked. Attempted to modify protected control directory: ${cmd}`,
        };
      }
    }
  });
}
