#!/usr/bin/env node
"use strict";

const fs = require("node:fs");
const path = require("node:path");

const SOURCE_URL = "https://publicsuffix.org/list/public_suffix_list.dat";
const outputPath = path.join(__dirname, "..", "public-suffix-list.js");

async function main() {
  const inputPath = process.argv[2];
  const source = inputPath
    ? fs.readFileSync(path.resolve(inputPath), "utf8")
    : await fetch(SOURCE_URL).then((response) => {
        if (!response.ok)
          throw new Error(`PSL download failed: HTTP ${response.status}`);
        return response.text();
      });
  const begin = source.indexOf("// ===BEGIN ICANN DOMAINS===");
  const privateBegin = source.indexOf("// ===BEGIN PRIVATE DOMAINS===");
  const privateEnd = source.indexOf("// ===END PRIVATE DOMAINS===");
  if (begin < 0 || privateBegin < 0 || privateEnd < 0) {
    throw new Error("Source is missing expected ICANN or private PSL sections");
  }
  const body = source.slice(begin, privateEnd);
  const rules = body
    .split(/\r?\n/)
    .map((line) => line.trim().toLowerCase())
    .filter((line) => line && !line.startsWith("//"))
    .map((rule) => {
      const marker = rule.startsWith("!")
        ? "!"
        : rule.startsWith("*.")
          ? "*."
          : "";
      const domain =
        marker === "!" ? rule.slice(1) : marker === "*." ? rule.slice(2) : rule;
      return marker + new URL(`http://${domain}`).hostname;
    });
  if (rules.length < 5000)
    throw new Error(`Unexpectedly small PSL (${rules.length} rules)`);
  const generated = [
    "/* Generated from https://publicsuffix.org/list/public_suffix_list.dat.",
    " * Contains ICANN and PRIVATE rules under the Mozilla Public License 2.0.",
    " * Regenerate with: node tools/update-psl.js [local-public_suffix_list.dat]",
    " */",
    `window.CLEANINSPECT_PSL = ${JSON.stringify(rules, null, 2)};`,
    "",
  ].join("\n");
  fs.writeFileSync(outputPath, generated);
  console.log(`Wrote ${rules.length} PSL rules to ${outputPath}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
