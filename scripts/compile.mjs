import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const solc = require("solc");
const sourceFiles = [
  "src/CognisecBunkerFactory.sol",
  "src/CognisecBunkerUpgradeable.sol",
  "test/CognisecBunkerV2.sol",
];
const sources = Object.fromEntries(
  sourceFiles.map((file) => [file, { content: fs.readFileSync(file, "utf8") }]),
);
const input = {
  language: "Solidity",
  sources,
  settings: {
    optimizer: { enabled: true, runs: 200 },
    viaIR: true,
    outputSelection: { "*": { "*": ["abi", "evm.bytecode.object"] } },
  },
};

const output = JSON.parse(
  solc.compile(JSON.stringify(input), {
    import(specifier) {
      const projectImport = specifier.startsWith("../src/")
        ? path.resolve("src", specifier.slice("../src/".length))
        : path.resolve(specifier);
      const candidates = [projectImport, path.resolve("node_modules", specifier)];
      for (const candidate of candidates) {
        if (fs.existsSync(candidate)) {
          return { contents: fs.readFileSync(candidate, "utf8") };
        }
      }
      return { error: `Import not found: ${specifier}` };
    },
  }),
);
const errors = (output.errors ?? []).filter((diagnostic) => diagnostic.severity === "error");
if (errors.length > 0) {
  console.error(errors.map((diagnostic) => diagnostic.formattedMessage).join("\n"));
  process.exitCode = 1;
} else {
  const count = Object.values(output.contracts ?? {}).reduce(
    (total, contracts) => total + Object.keys(contracts).length,
    0,
  );
  console.log(`Compiled ${count} contracts with the optimized IR pipeline.`);
}
