# codeql-queries

<!-- markdownlint-disable -->
<div align="center">

[![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)](https://github.com/advanced-security/codeql-queries)
[![GitHub Actions](https://img.shields.io/github/actions/workflow/status/advanced-security/codeql-queries/release-main.yml?style=for-the-badge)](https://github.com/advanced-security/codeql-queries/actions/workflows/release-main.yml?query=branch%3Amain)
[![GitHub Issues](https://img.shields.io/github/issues/advanced-security/codeql-queries?style=for-the-badge)](https://github.com/advanced-security/codeql-queries/issues)
[![GitHub Stars](https://img.shields.io/github/stars/advanced-security/codeql-queries?style=for-the-badge)](https://github.com/advanced-security/codeql-queries)
[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)

</div>

This is the GitHub's Field Team's Custom CodeQL Queries, Suites, and Configurations repository.

## Usage

### Actions

To add the field CodeQL packs in Actions, you only will need to add the following `packs` or `config-file`:

**Actions using packs argument:**

```yaml
# standard pack
packs: +advanced-security/codeql-${{ matrix.language }}@latest
# extension pack
packs: +advanced-security/codeql-${{ matrix.language }}-extensions@latest
```

**Configuration file (multi-language, all packs):**

```yaml
# standard packs, extensions, and extra packs
config-file: advanced-security/codeql-queries/config/codeql.yml@main
```

### CodeQL CLI

To use the Field queries with the CodeQL CLI, you need to do the following:

```bash
codeql pack download "advanced-security/codeql-$LANGUAGE@latest"
# ... init / setup
codeql database analyze \
    $CODEQL_DATABASE \
    "advanced-security/codeql-$LANGUAGE"
```

## License

This project is licensed under the terms of the MIT open source license. Please refer to [MIT](./LICENSE) for the full terms.

## Contributors

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->
<!-- prettier-ignore-start -->
<!-- markdownlint-disable -->
<table>
  <tbody>
    <tr>
      <td align="center" valign="top" width="14.28%"><a href="https://geekmasher.dev/"><img src="https://avatars.githubusercontent.com/u/2772944?v=4?s=100" width="100px;" alt="Mathew Payne"/><br /><sub><b>Mathew Payne</b></sub></a><br /><a href="https://github.com/advanced-security/codeql-queries/commits?author=GeekMasher" title="Code">💻</a> <a href="https://github.com/advanced-security/codeql-queries/commits?author=GeekMasher" title="Documentation">📖</a> <a href="#maintenance-GeekMasher" title="Maintenance">🚧</a> <a href="#research-GeekMasher" title="Research">🔬</a> <a href="#security-GeekMasher" title="Security">🛡️</a> <a href="#tool-GeekMasher" title="Tools">🔧</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## Support

Please [create GitHub issues](https://github.com/advanced-security/brew-dependency-submission-action) for any feature requests, bugs, or documentation problems.
