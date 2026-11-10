# Releasing

The Surveyor is released from a tag. The workflow does the boring parts, but
two things are deliberately left to a human: the tag itself, and PyPI.

## What the workflow does

`.github/workflows/release.yml` runs when a `v*` tag is pushed, and refuses to
do anything until it agrees with itself:

1. **The tag and the package agree.** `pyproject.toml`'s `version` must equal
   the tag with its `v` removed. A tag that disagrees is a mistake worth
   stopping on, because PyPI would reject it anyway — and a half-finished
   release is worse than no release.
2. **The suite still passes.** The same tests CI runs.
3. **Build and check.** `python -m build`, then `twine check dist/*`.
4. **Publish to PyPI**, if a trusted publisher is configured (see below).
5. **Release notes.** The section of `CHANGELOG.md` for that version is
   extracted, so the release body is the version's own notes rather than the
   whole file. The workflow also attaches the generated notes and the built
   distributions.
6. **GitHub release.** Always made, even when PyPI is not configured: the
   release notes and the artifacts live there.

To publish a version:

```bash
# 1. the version in the package
$EDITOR pyproject.toml            # version = "1.2.0"

# 2. the changelog section for it
$EDITOR CHANGELOG.md              # "## [1.2.0] — 2026-11-10"

# 3. the commit, through a pull request
git switch -c release/1.2.0
git commit -am "release: 1.2.0"
git push -u origin release/1.2.0
gh pr create --fill

# 4. the tag, once the pull request is merged and green
git tag -a v1.2.0 -m "The Surveyor 1.2.0"
git push origin v1.2.0
```

The workflow can also be dispatched by hand for an existing tag:

```bash
gh workflow run release.yml -f tag=v1.2.0
```

## Publishing to PyPI: the one manual step

PyPI is reached with [trusted publishing][trusted]: the workflow presents an
OIDC token, and PyPI decides whether to trust it. That trust is configured on
PyPI's side, per repository, and cannot be granted from inside the repository.
Until it exists, the publish step fails, the workflow says so in a warning,
and the GitHub release is still made.

To set it up, once, on PyPI:

1. Create the project (the name `the-surveyor` must still be available).
2. Add a **pending publisher** for:

   | Field | Value |
   | --- | --- |
   | PyPI project name | `the-surveyor` |
   | Owner | `hamanakam1` |
   | Repository name | `the-surveyor` |
   | Workflow name | `release.yml` |
   | Environment name | `release` |

   The environment name matters: the workflow's publish job runs in an
   environment called `release`, and PyPI matches the environment as part of
   the publisher identity.

3. Push a tag. PyPI sends a one-time code, the publisher becomes active, and
   from then on the workflow publishes on its own.

The project name on PyPI can differ from the repository name if
`pyproject.toml` says so, but the two must not drift: the workflow checks the
tag against `version`, and PyPI checks the distribution name against the
project.

## Verifying a release

```bash
pip install the-surveyor==1.2.0
surveyor --version
surveyor scan --ascii          # and read the plat it draws
```

[trusted]: https://docs.pypi.org/trusted-publishers/
