# CSharp (C#)

## Queries

<!-- AUTOMATION-QUERIES -->
| Name | Severity | Path |
| :--- | :------- | :--- |
| `Hardcoded Salt` | Unknown / 6.1 | `csharp/CWE-760/HardcodedSalt.ql` |
| `Audit: Usage of Command Injection sink` | Unknown / 2.0 | `csharp/CWE-078/CommandInjectionAudit.ql` |
| `Audit: Use of Code Injection sink` | Unknown / 2.0 | `csharp/CWE-094/CodeInjectionAudit.ql` |
| `Audit: Usage of Insecure XML Parser` | Unknown / 2.0 | `csharp/CWE-611/UnsafeXMLResolverAudit.ql` |
| `Use of Cryptographically Weak Hash Algorithms` | Medium / 5.0 | `csharp/CWE-328/WeakHashingAlgorithms.ql` |
| `Audit: Usage of Unsafe Deserialize sink` | Unknown / 2.0 | `csharp/CWE-502/UnsafeDeserializationAudit.ql` |


<!-- AUTOMATION-QUERIES -->

## Query Suites
<!-- AUTOMATION-SUITES -->
| Name | Queries Count | Description | Path |
| :--- | :---- | :--- | :--- |
| `default` | 54 | Default Query Suite | `codeql/csharp/ql/src/codeql-suites/code-scanning` |
| `extended` | 71 | Security Extended Suite | `codeql/csharp/ql/src/codeql-suites/security-extended` |
| `experimental` | 91 | Security Experimental Suite | `codeql/csharp/ql/src/codeql-suites/security-experimental` |
| `quality` | 172 | Security and Quality Extended Suite | `codeql/csharp/ql/src/codeql-suites/security-and-quality` |
| `super-extended` | 1 | Security Extended with Experimental and Custom Queries Suite | `advanced-security/codeql-queries/csharp/suites/codeql-csharp.qls@main` |
| `audit` | 6 | Security Audit Query Suite | `advanced-security/codeql-queries/csharp/suites/codeql-csharp-audit.qls@main` |


<!-- AUTOMATION-SUITES -->