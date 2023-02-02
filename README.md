# codeql-queries
GitHub's Field Team's CodeQL Custom Queries, Suites, and Configurations

## Getting Started

### Field Queries

To enabled and use the GitHub Field Team queries, you can easily add the following configuration file as part of Actions:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    config-file: advanced-security/codeql-queries/config/codeql.yml@main
```

If you want to use any of the queries but you are using your own configuration file, please just add use statements like the following:

```yaml
name: "My Custom Configuration File"

queries:
    # Simple Query
    - uses: advanced-security/codeql-queries/{LANGUAGE}/CWE-{CWEID}/{QUERY_NAME}.ql@main
    # Standard Query Suite
    - uses: advanced-security/codeql-queries/{LANGUAGE}/suites/codeql-{LANGUAGE}.qls@main
    # Audit queries
    - uses: advanced-security/codeql-queries/{LANGUAGE}/suites/codeql-{LANGUAGE}-audit.qls@main
```

*Note: Referencing the queries directly like this will cause an query compile step and will slow down your analysis*

### Field Audit / Debugging Queries

To enable and use the audit queries from the GitHub Field Security team, you can add the following configuration file to your Action:

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    config-file: advanced-security/codeql-queries/config/codeql-audit.yml@main
```

