# Java

## Queries

<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Resolving XML external entity in user-controlled data` | Unknown / 6.0 | `java/CWE-611/XXELocal.ql` |
| `Customized Cross-site scripting` | Unknown / 6.1 | `java/CWE-079/XSSJSP.ql` |
| `Customized Cross-site scripting` | Unknown / 6.1 | `java/CWE-079/XSSJSPLenient.ql` |
| `Base64 Encoding of Sensitive Information` | High / 8.0 | `java/CWE-326/Base64Encryption.ql` |
| `Use of Cryptographically Weak Pseudo-Random Number Generator` | Medium / 6.0 | `java/CWE-338/WeakPRNG.ql` |
| `Sensitive information exposure through logging` | Unknown / 8.0 | `java/CWE-532/SensitiveInformation.ql` |
| `Hard-coded password field` | Unknown / 9.8 | `java/CWE-798/HardcodedPasswordsInProperties.ql` |
| `RCE in Log4j CVE-2021-44228` | Unknown / 9.9 | `java/CWE-094/CVE-2021-44228.ql` |
| `Cross-site scripting` | Unknown / 6.1 | `java/examples/XSSCustomSanitizer.ql` |


<!-- AUTOMATION-QUERIES -->

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 49 | Default Query Suite | `code-scanning` |
| `extended` | 73 | Security Extended Suite | `security-extended` |
| `quality` | 193 | Security and Quality Extended Suite | `security-and-quality` |
| `local-variants` | 85 | Security Extended with local variants enabled | `advanced-security/codeql-queries/java/suites/codeql-java-local.qls@main` |
| `super-extended` | 109 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/java/suites/codeql-java.qls@main` |
| `extremely-extended` | 232 | Extremely Extended with Experimental, Static, and Custom Queries Suite | `advanced-security/codeql-queries/java/suites/codeql-java-all.qls@main` |


<!-- AUTOMATION-SUITES -->
