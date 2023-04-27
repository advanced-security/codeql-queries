# Field Data Extensions

## Usage

```yaml
packs: advanced-security/codeql-${{ matrix.language }}-extensions
```

**Step Example:**

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: ${{ matrix.language }}
    packs: advanced-security/codeql-${{ matrix.language }}-extensions
```

## Extension Summary

| Language                                     |                 Projects                  |
| :------------------------------------------- | :---------------------------------------: |
| [java](./codeql-java-extensions)             | [104](./codeql-java-extensions/generated) |
| [csharp](./codeql-csharp-extensions)         |  [6](./codeql-java-extensions/generated)  |
| [javascript](./codeql-javascript-extensions) |  [0](./codeql-java-extensions/generated)  |
