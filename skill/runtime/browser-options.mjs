/** Import this helper from a Puppeteer test. It does NOT install Puppeteer.
 * Example:
 *   import puppeteer from 'puppeteer-core';
 *   import { browserOptions } from '/opt/pi-lab/browser-options.mjs';
 *   const browser = await puppeteer.launch(browserOptions());
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

export function browserOptions(extra = {}) {
  const forbidden = ['--no-sandbox', '--disable-namespace-sandbox', '--disable-seccomp-filter-sandbox', '--disable-setuid-sandbox', '--single-process'];
  if (process.env.CHROME_NO_SANDBOX !== '1' && (extra.args || []).some(arg => forbidden.includes(arg.split('=')[0]))) {
    throw new Error('Sandbox-disabling browser arguments require the explicit sandbox opt-out');
  }
  const executablePath = process.env.PUPPETEER_EXECUTABLE_PATH || process.env.CHROME_BIN ||
    (process.platform === 'darwin'
      ? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
      : '/usr/bin/chromium');
  fs.accessSync(executablePath, fs.constants.X_OK);
  const args = process.platform === 'linux' ? ['--disable-dev-shm-usage'] : [];
  // Explicit opt-in only. Container isolation is NOT the Chromium sandbox.
  if (process.env.CHROME_NO_SANDBOX === '1') args.push('--no-sandbox');
  if (process.env.CHROME_SOFTWARE_WEBGL === '1') {
    args.push('--use-gl=angle', '--use-angle=swiftshader-webgl', '--enable-unsafe-swiftshader');
  }
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'pi-chromium-'));
  return {...extra, executablePath, headless: true, userDataDir: profile,
          args: [...args, ...(extra.args || [])]};
}
