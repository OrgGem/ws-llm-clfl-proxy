import { readFile, stat, writeFile } from "node:fs/promises";
import path from "node:path";

const [inputPath, outputPath] = process.argv.slice(2);
if (!inputPath || !outputPath) {
  throw new Error("Usage: node scripts/extract-worker-bundle.mjs <wrangler-outfile> <worker.js>");
}

const multipart = await readFile(inputPath, "utf8");
const boundary = multipart.match(/^(--[^\r\n]+)/)?.[1];
if (!boundary) throw new Error(`Wrangler output at ${inputPath} is not multipart data`);
const partHeader = /Content-Disposition: form-data; name="index\.js"; filename="index\.js"\r?\nContent-Type: application\/javascript\+module\r?\n\r?\n/i;
const header = partHeader.exec(multipart);
if (!header) throw new Error(`Wrangler output at ${inputPath} has no index.js module`);

const bodyStart = header.index + header[0].length;
const bodyEnd = multipart.indexOf(`\r\n${boundary}`, bodyStart);
if (bodyEnd < 0) throw new Error(`Wrangler output at ${inputPath} has no module terminator`);
const moduleSource = multipart.slice(bodyStart, bodyEnd);
if (moduleSource.length === 0 || moduleSource.includes(`\r\n${boundary}`)) {
  throw new Error(`Extracted Worker module from ${inputPath} does not look like JavaScript`);
}
await writeFile(outputPath, moduleSource, "utf8");
const { size } = await stat(outputPath);
console.log(`${path.basename(outputPath)}: ${size} bytes`);
