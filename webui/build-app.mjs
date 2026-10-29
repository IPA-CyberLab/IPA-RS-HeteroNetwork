import { mkdtemp, readFile, rename, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { build } from "esbuild";

const webuiDirectory = path.dirname(fileURLToPath(import.meta.url));
const sourceCss = path.join(webuiDirectory, "src/styles.css");
const temporaryDirectory = await mkdtemp(path.join(tmpdir(), "heteronet-ui-"));
const compiledCss = path.join(temporaryDirectory, "styles.css");
try {
  await promisify(execFile)(process.execPath, [path.join(webuiDirectory, "../node_modules/@tailwindcss/cli/dist/index.mjs"), "-i", sourceCss, "-o", compiledCss, "--minify"], { cwd: webuiDirectory });
  const css = await readFile(compiledCss, "utf8");
  await build({
    entryPoints: [path.join(webuiDirectory, "src/main.jsx")],
    outfile: path.join(webuiDirectory, "app.js"),
    bundle: true, minify: true, sourcemap: false, legalComments: "external",
    platform: "browser", target: ["es2020"], external: ["/ui/*"], jsx: "automatic",
    define: { "process.env.NODE_ENV": '"production"' }, logLevel: "info",
    plugins: [{ name: "compiled-daisyui", setup(build) {
      build.onLoad({ filter: /[/\\]src[/\\]styles\.css$/ }, () => ({contents: css, loader: "css", resolveDir: path.join(webuiDirectory, "src")}));
    }}],
  });
  await rename(path.join(webuiDirectory, "app.css"), path.join(webuiDirectory, "styles.css"));
  try { await rename(path.join(webuiDirectory, "app.css.LEGAL.txt"), path.join(webuiDirectory, "styles.css.LEGAL.txt")); }
  catch (error) { if (error.code !== "ENOENT") throw error; await rm(path.join(webuiDirectory, "styles.css.LEGAL.txt"), { force: true }); }
} finally { await rm(temporaryDirectory, {recursive: true, force: true}); }
