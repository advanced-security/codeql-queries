# Python

## Queries
<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Uncontrolled command line` | Critical / 10.0 | `python/CWE-078/CommandInjectionLocal.ql` |
| `SQL query built from user-controlled sources` | Critical / 10.0 | `python/CWE-089/SqlInjectionLocal.ql` |
| `Code injection` | Critical / 10.0 | `python/CWE-094/CodeInjectionLocal.ql` |
| `Deserializing untrusted input` | High / 8.0 | `python/CWE-502/UnsafeDeserializationLocal.ql` |
| `Uncontrolled command line` | Low / 2.5 | `python/CWE-078/CommandInjectionStatic.ql` |
| `SQL query built from user-controlled sources` | Unknown / 8.8 | `python/CWE-089/SqlInjectionHeuristic.ql` |
| `Code injection` | Low / 2.5 | `python/CWE-094/CodeInjectionStatic.ql` |
| `Python user-controlled format string` | Unknown / 1.0 | `python/CWE-133/format_string.ql` |
| `Use of Cryptographically Weak HMAC Algorithm` | Medium / 5.0 | `python/CWE-327/WeakHMacAlgorithms.ql` |
| `Use of a broken or weak cryptographic algorithm` | Medium / 5.0 | `python/CWE-327/WeakHashingAlgorithms.ql` |
| `Use of Cryptographically Weak Pseudo-Random Number Generator` | Medium / 6.0 | `python/CWE-338/WeakPRNG.ql` |
| `Deserializing untrusted input` | Low / 2.5 | `python/CWE-502/UnsafeDeserializationStatic.ql` |
| `Deserializing XML from local file` | Unknown / 6.0 | `python/CWE-502/XMLLocalFileStatic.ql` |
| `Deserializing XML from user-controlled filename` | Unknown / 6.0 | `python/CWE-502/XMLLocalFileTaint.ql` |
| `Deserializing XML from user-controlled data` | Unknown / 6.0 | `python/CWE-502/XMLLocalStringTaint.ql` |
| `Dangerous Functions` | Low / 2.5 | `python/CWE-676/DangerousFunctions.ql` |
| `Insufficient Logging` | Low / 1.0 | `python/CWE-778/InsufficientLogging.ql` |
| `Hard-coded credentials` | Medium / 5.9 | `python/CWE-798/HardcodedFrameworkSecrets.ql` |
| `Mass assignment` | High / 8.0 | `python/CWE-915/MassAssignment.ql` |
| `Mass assignment` | High / 2.0 | `python/CWE-915/MassAssignmentLocal.ql` |
| `Partial Path Query from Sink` | Low / 1.0 | `python/debugging/PartialPathsFromSink.ql` |
| `Partial Path Query from Source` | Low / 1.0 | `python/debugging/PartialPathsFromSource.ql` |


<!-- AUTOMATION-QUERIES -->
## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 38 | Default Query Suite | `codeql/python/ql/src/codeql-suites/code-scanning` |
| `extended` | 45 | Security Extended Suite | `codeql/python/ql/src/codeql-suites/security-extended` |
| `quality` | 167 | Security and Quality Extended Suite | `codeql/python/ql/src/codeql-suites/security-and-quality` |
| `local-variants` | 49 | Security Extended with local variants enabled | `advanced-security/codeql-queries/python/suites/codeql-python-local.qls@main` |
| `super-extended` | 73 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/python/suites/codeql-python.qls@main` |


<!-- AUTOMATION-SUITES -->
