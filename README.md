# codeql-queries

<!-- markdownlint-disable -->
<div align="center">

[![GitHub](https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white)](https://github.com/advanced-security/codeql-queries)
[![GitHub Actions](https://img.shields.io/github/actions/workflow/status/advanced-security/codeql-queries/release-main.yml?style=for-the-badge)](https://github.com/advanced-security/codeql-queries/actions/workflows/release-main.yml?query=branch%3Amain)
[![GitHub Issues](https://img.shields.io/github/issues/advanced-security/codeql-queries?style=for-the-badge)](https://github.com/advanced-security/codeql-queries/issues)
[![GitHub Stars](https://img.shields.io/github/stars/advanced-security/codeql-queries?style=for-the-badge)](https://github.com/advanced-security/codeql-queries)
[![Licence](https://img.shields.io/github/license/Ileriayo/markdown-badges?style=for-the-badge)](./LICENSE)

</div>
<!-- markdownlint-restore -->

This is the GitHub's Field Team's Custom CodeQL Queries, Suites, and Configurations repository.

## Usage

### Actions

To add the field CodeQL packs in Actions, you only will need to add the following `packs` or `config-file`:

**Actions using packs argument:**

```yaml
# standard pack
packs: +advanced-security/codeql-${{ matrix.language }}
# extension pack
packs: +advanced-security/codeql-${{ matrix.language }}-extensions
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
      <td align="center" valign="top" width="20%"><a href="https://geekmasher.dev"><img src="https://avatars.githubusercontent.com/u/2772944?v=3?s=100" width="100px;" alt="Mathew Payne"/><br /><sub><b>Mathew Payne</b></sub></a><br /><a href="https://github.com/advanced-security/codeql-queries/commits?author=geekmasher" title="Code">💻</a> <a href="#research-geekmasher" title="Research">🔬</a> <a href="#maintenance-geekmasher" title="Maintenance">🚧</a> <a href="#security-geekmasher" title="Security">🛡️</a></td>
      <td align="center" valign="top" width="20%"><a href="https://aegilops.github.io/"><img src="https://avatars.githubusercontent.com/u/41705651?v=3?s=100" width="100px;" alt="Paul Hodgkinson"/><br /><sub><b>Paul Hodgkinson</b></sub></a><br /><a href="https://github.com/advanced-security/codeql-queries/commits?author=aegilops" title="Code">💻</a> <a href="#ideas-aegilops" title="Ideas, Planning, & Feedback">🤔</a> <a href="#research-aegilops" title="Research">🔬</a> <a href="#security-aegilops" title="Security">🛡️</a></td>
      <td align="center" valign="top" width="20%"><a href="https://felickz.github.io/"><img src="https://avatars.githubusercontent.com/u/1760475?v=3?s=100" width="100px;" alt="Chad Bentz"/><br /><sub><b>Chad Bentz</b></sub></a><br /><a href="https://github.com/advanced-security/codeql-queries/commits?author=felickz" title="Code">💻</a> <a href="#example-felickz" title="Examples">💡</a> <a href="#ideas-felickz" title="Ideas, Planning, & Feedback">🤔</a></td>
      <td align="center" valign="top" width="20%"><a href="https://securing.dev"><img src="https://avatars.githubusercontent.com/u/22803099?v=4" width="100px;" alt="Keith Hoodlet"/><br /><sub><b>Keith Hoodlet</b></sub></a><br /><a href="https://github.com/advanced-security/codeql-queries/commits?author=securingdev" title="Code">💻</a> <a href="#research-securingdev" title="Research">🔬</a> <a href="#maintenance-securingdev" title="Maintenance">🚧</a> <a href="#security-securingdev" title="Security">🛡️</a></td>
    </tr>
  </tbody>
</table>

<!-- markdownlint-restore -->
<!-- prettier-ignore-end -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

## Support

Please [create GitHub issues](https://github.com/advanced-security/brew-dependency-submission-action) for any feature requests, bugs, or documentation problems.
