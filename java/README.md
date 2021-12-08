# Java

## Queries

<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Base64 Encoding of Sensitive Information` | High / 8.0 | `java/CWE-326/Base64Encryption.ql` |
| `Hard-coded password field` | Unknown / 9.8 | `java/CWE-798/HardcodedPasswordsInProperties.ql` |
| `Sensitive information exposure through logging` | Unknown / 8.0 | `java/CWE-532/SensitiveInformation.ql` |
| `Use of Cryptographically Weak Pseudo-Random Number Generator` | Medium / 6.0 | `java/CWE-338/WeakPRNG.ql` |
| `Customized Cross-site scripting` | Unknown / 6.1 | `java/CWE-079/XSSJSP.ql` |
| `Customized Cross-site scripting` | Unknown / 6.1 | `java/CWE-079/XSSJSPLenient.ql` |


<!-- AUTOMATION-QUERIES -->

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 44 | Default Query Suite | `code-scanning` |
| `extended` | 64 | Security Extended Suite | `security-extended` |
| `quality` | 184 | Security and Quality Extended Suite | `security-and-quality` |
| `local-variants` | 75 | Security Extended with local variants enabled | `advanced-security/codeql-queries/java/suites/codeql-java-local.qls@main` |
| `super-extended` | 102 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/java/suites/codeql-java.qls@main` |


<!-- AUTOMATION-SUITES -->
