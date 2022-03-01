# codeql-queries
GitHub's Field Team's CodeQL Custom Queries, Suites, and Configurations

## Getting Started

Add the GitHub Field Team's config-file as part of Actions.

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v1
  with:
    config-file: advanced-security/codeql-queries/config/codeql.yml@main
```

### Bundle

```yaml
- name: Download Custom CodeQL Bundle
  uses: advanced-security/codeql-queries@main
  env:
    GITHUB_TOKEN: ${{ github.token }}

- name: Initialize CodeQL
  uses: github/codeql-action/init@v1
  with:
    languages: ${{ matrix.language }}
    config-file: advanced-security/codeql-queries/config/codeql.yml@main
    tools: customized-codeql-bundle.tar.gz
```

### Local Development

```bash
git clone --recursive https://github.com/advanced-security/codeql-queries.git && code .
```
