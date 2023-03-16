# JavaScript

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 88 | Default Query Suite | `codeql/javascript/ql/src/codeql-suites/code-scanning` |
| `extended` | 105 | Security Extended Suite | `codeql/javascript/ql/src/codeql-suites/security-extended` |
| `quality` | 203 | Security and Quality Extended Suite | `codeql/javascript/ql/src/codeql-suites/security-and-quality` |
| `super-extended` | 128 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/javascript/suites/codeql-javascript.qls@main` |
| `audit` | 5 | Security Audit Query Suite | `advanced-security/codeql-queries/javascript/suites/codeql-javascript-audit.qls@main` |


<!-- AUTOMATION-SUITES -->

## Queries
<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Use of unsafe superjson parse or deserialize functions` | Unknown / 10.0 | `javascript/CVE-2022-23631/SuperJson.ql` |
| `Reflected cross-site scripting` | Unknown / 6.1 | `javascript/CWE-079/XSSReact.ql` |
| `Command Injection Sink used` | Unknown / 3.0 | `javascript/CWE-078/CommandInjectionAudit.ql` |
| `Possible Reflected Cross-Site Scripting` | Unknown / 3.0 | `javascript/CWE-079/XSSAudit.ql` |
| `Unsafe Deserialization sink used` | Unknown / 3.0 | `javascript/CWE-502/UnsafeDeserializationAudit.ql` |
| `XML External Entity sink used` | Unknown / 3.0 | `javascript/CWE-611/XXEAudit.ql` |
| `Using JS Eval` | Unknown / 2.0 | `javascript/CWE-676/UseOfEval.ql` |


<!-- AUTOMATION-QUERIES -->
