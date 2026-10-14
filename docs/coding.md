# Coding and documentation conventions

Author: Jason Stys.

Task-appropriate languages: Python for typed portable offline contracts/review/tests/orchestration; YAML for actual Falco/audit/workflow configuration; Bash for bounded native container activity; SQL for evidence; HTML/CSS for inert human review. No unnecessary language wrappers.

Self-documenting names, immutable records, explicit health states, narrow functions and visible trust boundaries. Header purpose plus exact generated physical line map in every authored Python/SQL/Bash/YAML source. Python uses AST definitions/parameters/stored variable/attribute locations; SQL/Bash/YAML are lexical indexes, not semantic parsing. Functions/classes include purpose documentation; important configuration/probe sections explain safety intent.

Generate code maps after Ruff formatting: python scripts/code_map.py. CI --check prevents drift. Stage reviewed public files, then python scripts/file_guide.py makes exact complete README purpose inventory; unknown purposes fail. Long line maps are generated, not manually updated.

Strict mypy runtime types, Ruff style/imports, bounded properties and actual native oracles. Separate “validation passed” from “secure/compliant.” Pinned full development graph, official artifact hashes and immutable Actions commits; no cache/artifact persistence.
