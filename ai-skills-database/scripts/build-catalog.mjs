// Builds catalog.json from skills/<scenario>/<skill>/SKILL.md and checks every skill on the way.
// Usage: node scripts/build-catalog.mjs [output-path]   (default: catalog.json next to this repo's root)
// Exits 1 on any problem, so it can run in CI.
import { readdirSync, readFileSync, writeFileSync, existsSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const out = process.argv[2] ?? join(root, "catalog.json");
const scenarios = JSON.parse(readFileSync(join(root, "scenarios.json"), "utf8"));
const known = new Set(scenarios.map((s) => s.id));

// Tiny front-matter reader for the subset the skills use: flat keys, quoted or plain values, one `metadata:` block.
function parse(text, file) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n/);
  if (!m) throw new Error(`${file}: missing front matter`);
  const fm = { metadata: {} };
  let inMeta = false;
  for (const line of m[1].split("\n")) {
    const meta = line.match(/^  ([a-z-]+): (.*)$/);
    if (inMeta && meta) { fm.metadata[meta[1]] = meta[2].trim(); continue; }
    const kv = line.match(/^([a-z-]+):\s*(.*)$/);
    if (!kv) continue;
    inMeta = kv[1] === "metadata";
    if (!inMeta) fm[kv[1]] = kv[2].replace(/^"(.*)"$/, "$1");
  }
  return { fm, body: text.slice(m[0].length).trim() };
}

const problems = [];
const skills = [];
for (const scenario of readdirSync(join(root, "skills"))) {
  const dir = join(root, "skills", scenario);
  if (!statSync(dir).isDirectory()) continue;
  if (!known.has(scenario)) problems.push(`skills/${scenario}: scenario is not listed in scenarios.json`);
  for (const name of readdirSync(dir)) {
    const file = join(dir, name, "SKILL.md");
    if (!existsSync(file)) { problems.push(`skills/${scenario}/${name}: no SKILL.md`); continue; }
    const text = readFileSync(file, "utf8");
    try {
      const { fm, body } = parse(text, file);
      if (fm.name !== name) problems.push(`${file}: name "${fm.name}" must match the folder name`);
      if (!fm.description || fm.description.length < 40) problems.push(`${file}: description is missing or too short`);
      if (fm.description && fm.description.length > 400) problems.push(`${file}: description is longer than 400 characters`);
      if (fm.metadata.scenario !== scenario) problems.push(`${file}: metadata.scenario must be "${scenario}"`);
      for (const h of ["## When to use", "## Steps", "## Quality checks"]) if (!body.includes(h)) problems.push(`${file}: missing section "${h}"`);
      skills.push({
        id: name,
        scenario,
        name,
        description: fm.description,
        tags: (fm.metadata.tags ?? "").split(",").map((t) => t.trim()).filter(Boolean),
        path: `skills/${scenario}/${name}/SKILL.md`,
        content: text.trim() + "\n",
      });
    } catch (e) {
      problems.push(String(e.message ?? e));
    }
  }
}

if (problems.length) {
  console.error(problems.join("\n"));
  process.exit(1);
}
skills.sort((a, b) => a.scenario.localeCompare(b.scenario) || a.name.localeCompare(b.name));
writeFileSync(out, JSON.stringify({ scenarios, skills }, null, 2) + "\n");
console.log(`${skills.length} skills in ${scenarios.length} scenarios -> ${out}`);
