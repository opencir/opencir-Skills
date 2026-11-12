# Contributing a skill

1. Pick the scenario in `scenarios.json` the skill belongs to. If none fits, open an issue first; new scenarios also need a solution on the website.
2. Create `skills/<scenario>/<skill-name>/SKILL.md`. The folder name and the `name` field must match and use lowercase letters and hyphens.
3. Start with this front matter:

   ```
   ---
   name: your-skill-name
   description: "What it does and when to use it, in one or two sentences."
   metadata:
     scenario: the-scenario-id
     tags: two, or three, tags
   ---
   ```

4. Write the body with these sections: `When to use`, `Inputs to collect`, `Steps`, `Output format`, `Quality checks`.
5. Run `node scripts/build-catalog.mjs` and commit the updated `catalog.json` together with the skill.

## Rules

- Write your own text. Do not copy skills, descriptions or collections from other catalogs or paid libraries, and do not paste material you do not have the right to share.
- No secrets, keys, private URLs or personal data.
- Security skills are for defensive use only.
- Keep descriptions specific: the description decides when an agent loads the skill.
