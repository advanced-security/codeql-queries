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
