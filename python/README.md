# Python

## Queries
<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Uncontrolled command line` | Critical / 10.0 | `python/CWE-078/CommandInjectionLocal.ql` |
| `SQL query built from user-controlled sources` | Critical / 10.0 | `python/CWE-089/SqlInjectionLocal.ql` |
| `Code injection` | Critical / 10.0 | `python/CWE-094/CodeInjectionLocal.ql` |
| `Deserializing untrusted input` | High / 8.0 | `python/CWE-502/UnsafeDeserializationLocal.ql` |
| `Uncontrolled command line` | Medium / 6.0 | `python/CWE-078/CommandInjectionStatic.ql` |
| `Code injection` | Medium / 6.0 | `python/CWE-094/CodeInjectionStatic.ql` |
| `Use of a broken or weak cryptographic algorithm` | Medium / 5.0 | `python/CWE-327/WeakHashingAlgorithms.ql` |
| `Use of Cryptographically Weak Pseudo-Random Number Generator` | Medium / 6.0 | `python/CWE-338/WeakPRNG.ql` |
| `Deserializing untrusted input` | Medium / 6.0 | `python/CWE-502/UnsafeDeserializationStatic.ql` |
| `Dangerous Functions` | Low / 2.5 | `python/CWE-676/DangerousFunctions.ql` |
| `Insufficient Logging` | Low / 1.0 | `python/CWE-778/InsufficientLogging.ql` |
| `Hard-coded credentials` | Medium / 5.9 | `python/CWE-798/HardcodedFrameworkSecrets.ql` |


<!-- AUTOMATION-QUERIES -->
## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 31 | Default Query Suite | `code-scanning` |
| `extended` | 37 | Security Extended Suite | `security-extended` |
| `quality` | 159 | Security and Quality Extended Suite | `security-and-quality` |
| `local-variants` | 41 | Security Extended with local variants enabled | `advanced-security/codeql-queries/python/suites/codeql-python-local.qls@main` |
| `super-extended` | 61 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/python/suites/codeql-python.qls@main` |
| `extremely-extended` | 179 | Extremely Extended with Experimental, Static, and Custom Queries Suite | `advanced-security/codeql-queries/python/suites/codeql-python-all.qls@main` |


<!-- AUTOMATION-SUITES -->
