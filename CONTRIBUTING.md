# Contributing

## Development Setup

Requires Go 1.26 or later; `go.mod` pins the toolchain that CI uses.

```bash
make ci
```

runs everything CI runs: gofmt, `go mod tidy` check, `go vet`, staticcheck, the race-detected test suite, coverage, both example programs, a short fuzz pass over every fuzz target, and govulncheck. The individual targets are listed in the Makefile.

## Code Style

- `gofmt`, `go vet`, and `staticcheck` must pass
- Error messages use the format `"dkls23 FunctionName: description"` or `"frost FunctionName: description"`
- Exported types and functions carry GoDoc comments that cite the paper section or RFC section they implement

## Testing

- Maintain 90%+ test coverage
- Add tests for new public API functions and error paths
- Run with `-race` to catch concurrency issues
- Tests must assert protocol behaviour, not just the absence of errors; a tampered or malicious input should be shown to be rejected and attributed to the right party

## Pull Requests

- Keep PRs focused on a single change
- Include tests for new functionality, and for every security property a PR states in a comment, GoDoc, or `SECURITY.md`: the test that would fail if the property were false is the evidence, not the sentence
- Update `CHANGELOG.md`

## Security-Sensitive Changes

All code in `dkls23/` and `frost/` is security-critical. Changes to it must follow the cited specifications (the DKLS23 paper, RFC 9591, the FROST paper, and the papers they reference) rather than introduce new constructions, and must say which section they implement. Please coordinate with the maintainers before submitting large changes to these areas, and report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

When reviewing or changing this code, do not take a property on trust because a function name, a comment, an existing document, or a dependency's README asserts it. Two reviews of this repository found claims that had been read and repeated rather than tested. Find or write the test that would fail if the claim were false before relying on it; see rule 11 in [CLAUDE.md](CLAUDE.md).
