# Python

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 29 | Default Query Suite | `codeql/queries:codeql-suites/go-code-scanning` |
| `extended` | 31 | Security Extended Suite | `codeql/queries:codeql-suites/go-security-extended` |
| `experimental` | 46 | Security Experimental Suite | `codeql/queries:codeql-suites/go-security-experimental` |
| `quality` | 53 | Security and Quality Extended Suite | `codeql/queries:codeql-suites/go-security-and-quality` |
| `super-extended` | 2 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/go/suites/codeql-go.qls@main` |


<!-- AUTOMATION-SUITES -->

## Queries
<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Command built from user-controlled sources` | Unknown / 9.8 | `go/CWE-078/CommandInjection.ql` |
| `Log entries created from user input` | Unknown / 7.8 | `go/CWE-117/LogInjection.ql` |


<!-- AUTOMATION-QUERIES -->
