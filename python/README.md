# Python

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 38 | Default Query Suite | `codeql/python/ql/src/codeql-suites/code-scanning` |
| `extended` | 45 | Security Extended Suite | `codeql/python/ql/src/codeql-suites/security-extended` |
| `quality` | 167 | Security and Quality Extended Suite | `codeql/python/ql/src/codeql-suites/security-and-quality` |
| `local-variants` | 4 | Security Extended with local variants enabled | `advanced-security/codeql-queries/python/suites/codeql-python-local.qls@main` |
| `super-extended` | 7 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/python/suites/codeql-python.qls@main` |
| `audit` | 8 | Security Audit Query Suite | `advanced-security/codeql-queries/python/suites/codeql-python-audit.qls@main` |


<!-- AUTOMATION-SUITES -->

## Queries
<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Uncontrolled command line` | Critical / 10.0 | `python/CWE-078/CommandInjectionLocal.ql` |
| `SQL query built from user-controlled sources` | Critical / 10.0 | `python/CWE-089/SqlInjectionLocal.ql` |
| `Code injection` | Critical / 10.0 | `python/CWE-094/CodeInjectionLocal.ql` |
| `Deserializing untrusted input` | High / 8.0 | `python/CWE-502/UnsafeDeserializationLocal.ql` |
| `Python user-controlled format string` | Unknown / 1.0 | `python/CWE-133/format_string.ql` |
| `Use of Cryptographically Weak Pseudo-Random Number Generator` | Medium / 6.0 | `python/CWE-338/WeakPRNG.ql` |
| `Insufficient Logging` | Low / 1.0 | `python/CWE-778/InsufficientLogging.ql` |
| `Uncontrolled command line` | Low / 2.5 | `python/CWE-078/CommandInjectionAudit.ql` |
| `SQL query built from user-controlled sources` | Unknown / 8.8 | `python/CWE-089/SqlInjectionHeuristic.ql` |
| `Code injection` | Low / 2.5 | `python/CWE-094/CodeInjectionAudit.ql` |
| `Unknown/Unmodelled CodeQL Dependencies` | High / 1.0 | `python/CWE-1104/UnknownDeps.ql` |
| `Deserializing untrusted input` | Low / 2.5 | `python/CWE-502/UnsafeDeserializationAudit.ql` |
| `Deserializing XML from local file` | Unknown / 6.0 | `python/CWE-502/XMLLocalFileAudit.ql` |
| `Dangerous Functions` | Low / 2.5 | `python/CWE-676/DangerousFunctions.ql` |


<!-- AUTOMATION-QUERIES -->
