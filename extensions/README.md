# Field Data Extensions

## Usage

```yaml
packs: advanced-security/codeql-${{ matrix.language }}-extensions
```

#### Actions Step Example

```yaml
- name: Initialize CodeQL
  uses: github/codeql-action/init@v2
  with:
    languages: ${{ matrix.language }}
    packs: advanced-security/codeql-${{ matrix.language }}-extensions
```

#### CodeQL CLI

**Install the latest pack**

```bash
codeql pack download advanced-security/codeql-$LANGUAGE-extensions@latest
```

**Use pack in analysis:**

```bash
# ... init / setup
codeql database analyze \
    --extension-packs advanced-security/codeql-$LANGUAGE-extensions \
    $CODEQL_DATABASE \
    codeql/$LANGUAGE-queries
```

The `LANGUAGE` variable must be set to use the correct extension pack, point to the correct database, and add any other additional parameters to the command.


## Extension Summary

| Language                                     |                 Projects                  |
| :------------------------------------------- | :---------------------------------------: |
| [java](./codeql-java-extensions)             | [104](./codeql-java-extensions/generated) |
| [csharp](./codeql-csharp-extensions)         |  [6](./codeql-java-extensions/generated)  |
| [javascript](./codeql-javascript-extensions) |  [0](./codeql-java-extensions/generated)  |
