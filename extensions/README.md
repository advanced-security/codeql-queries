# Field Data Extensions

## Usage

```yaml
- name: Initialize CodeQL
    uses: github/codeql-action/init@v2
    with:
    languages: ${{ matrix.language }}
    packs: advanced-security/codeql-${{ matrix.language }}-extensions
```
