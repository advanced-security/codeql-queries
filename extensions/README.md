# Field Data Extensions

## Usage

```yaml
- name: Initialize CodeQL
    uses: github/codeql-action/init@v2
    with:
    languages: ${{ matrix.language }}
    packs: advanced-security/codeql-${{ matrix.language }}-extensions
```

## Generated Summaries

| Language                                     |                 Projects                  |
| :------------------------------------------- | :---------------------------------------: |
| [java](./codeql-java-extensions)             | [100](./codeql-java-extensions/generated) |
| [csharp](./codeql-csharp-extensions)         |  [5](./codeql-java-extensions/generated)  |
| [javascript](./codeql-javascript-extensions) |  [0](./codeql-java-extensions/generated)  |
