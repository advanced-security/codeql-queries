# Java

## Queries

<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Resolving XML external entity in user-controlled data` | Unknown / 6.0 | `java/CWE-611/XXELocal.ql` |
| `Uncontrolled data used in path expression` | Unknown / 7.5 | `java/CWE-021/TaintedPath.ql` |
| `Customized Cross-site scripting` | Unknown / 6.1 | `java/CWE-079/XSSJSP.ql` |
| `Customized Cross-site scripting` | Unknown / 6.1 | `java/CWE-079/XSSJSPLenient.ql` |
| `Base64 Encoding of Sensitive Information` | High / 8.0 | `java/CWE-326/Base64Encryption.ql` |
| `Use of Cryptographically Weak Pseudo-Random Number Generator` | Medium / 6.0 | `java/CWE-338/WeakPRNG.ql` |
| `Sensitive information exposure through logging` | Unknown / 8.0 | `java/CWE-532/SensitiveInformation.ql` |
| `Hard-coded password field` | Unknown / 9.8 | `java/CWE-798/HardcodedPasswordsInProperties.ql` |


<!-- AUTOMATION-QUERIES -->

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 66 | Default Query Suite | `codeql/java/ql/src/codeql-suites/code-scanning` |
| `extended` | 96 | Security Extended Suite | `codeql/java/ql/src/codeql-suites/security-extended` |
| `quality` | 216 | Security and Quality Extended Suite | `codeql/java/ql/src/codeql-suites/security-and-quality` |
| `local-variants` | 108 | Security Extended with local variants enabled | `advanced-security/codeql-queries/java/suites/codeql-java-local.qls@main` |
| `super-extended` | 132 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/java/suites/codeql-java.qls@main` |


<!-- AUTOMATION-SUITES -->
