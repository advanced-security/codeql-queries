/**
 * @name Use of Weak Hmac Algorithms
 * @description Use of Weak Hmac Algorithms
 * @kind problem
 * @problem.severity warning
 * @security-severity 4.0
 * @precision medium
 * @id cs/weak-hmac-algorithm
 * @tags security
 *       external/cwe/cwe-327
 */

import csharp
import github.crypto

from Crypto::HMacSigningAlgorithms algorithms
where algorithms.algorithm() = ["MD5", "SHA1"]
select algorithms, "Weak Hmac Algorithms"
