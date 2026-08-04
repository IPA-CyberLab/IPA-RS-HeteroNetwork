import { rename } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { build } from "esbuild";

const webuiDirectory = path.dirname(fileURLToPath(import.meta.url));
const outputCss = path.join(webuiDirectory, "app.css");
const outputCssLegal = `${outputCss}.LEGAL.txt`;

await build({
  entryPoints: [path.join(webuiDirectory, "src/main.jsx")],
  outfile: path.join(webuiDirectory, "app.js"),
  bundle: true,
  minify: true,
  sourcemap: false,
  legalComments: "external",
  platform: "browser",
  target: ["es2020"],
  external: ["/ui/*"],
  jsx: "automatic",
  define: {
    "process.env.NODE_ENV": '"production"',
  },
  logLevel: "info",
});

await rename(outputCss, path.join(webuiDirectory, "styles.css"));
await rename(outputCssLegal, path.join(webuiDirectory, "styles.css.LEGAL.txt"));
