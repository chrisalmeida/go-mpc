# AGENTS.md

This repository's instructions for agents and humans live in [CLAUDE.md](CLAUDE.md). It is the single source; do not duplicate or paraphrase its content here, so the two files cannot drift apart.

Read CLAUDE.md fully before changing or reviewing anything under `dkls23/` or `frost/`. In particular:

- **Rule 11, "Verify every claim; inherit none."** A function name, a comment, a GoDoc sentence, a `SECURITY.md` claim, an `AUDIT.md` resolution, or a dependency's README is a hypothesis, not evidence. Two reviews of this repository have found claims that were read and repeated rather than tested. Find or write the test that would fail if the claim were false before relying on it, and say in `AUDIT.md` what you tested and what you only read.
- **`make ci` must be green** before a change is finished, and the Documentation Duties section lists the documents that must match the code, including CLAUDE.md itself.
