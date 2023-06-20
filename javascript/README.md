# JavaScript

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 88 | Default Query Suite | `codeql/javascript/ql/src/codeql-suites/code-scanning` |
| `extended` | 105 | Security Extended Suite | `codeql/javascript/ql/src/codeql-suites/security-extended` |
| `quality` | 203 | Security and Quality Extended Suite | `codeql/javascript/ql/src/codeql-suites/security-and-quality` |
| `super-extended` | 4 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/javascript/suites/codeql-javascript.qls@main` |
| `audit` | 1 | Security Audit Query Suite | `advanced-security/codeql-queries/javascript/suites/codeql-javascript-audit.qls@main` |


<!-- AUTOMATION-SUITES -->

## Queries
<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Insecure or static IV used in cryptographic function with Node crypto module` | Unknown / 4.3 | `javascript/CWE-329/InsecureIV.ql` |
| `Use of unsafe superjson parse or deserialize functions` | Unknown / 10.0 | `javascript/CVE-2022-23631/SuperJson.ql` |
| `Unpinned tag for 3rd party Action in workflow` | Unknown / 9.3 | `javascript/CWE-829/UnpinnedActionsTag.ql` |
| `Reflected cross-site scripting` | Unknown / 6.1 | `javascript/CWE-079/XSSReact.ql` |


<!-- AUTOMATION-QUERIES -->
