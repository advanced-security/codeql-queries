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
# [optional]
- name: Get Latest Bundle
  id: init_bundle
  run: |
    CODEQL_BUNDLE_VERSION=$(curl --silent "https://api.github.com/repos/advanced-security/codeql-queries/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
    echo "::set-output name=tools::https://github.com/advanced-security/codeql-queries/releases/download/$CODEQL_BUNDLE_VERSION/customized-codeql-bundle.tar.gz"

- name: Initialize CodeQL
  uses: github/codeql-action/init@v1
  with:
    languages: ${{ matrix.language }}
    # This can be hardcoded with the a particular release `customized-codeql-bundle.tar.gz` URL
    tools: ${{ steps.init_bundle.outputs.tools }}
```

### Local Development

```bash
git clone --recursive https://github.com/advanced-security/codeql-queries.git && code .
```
