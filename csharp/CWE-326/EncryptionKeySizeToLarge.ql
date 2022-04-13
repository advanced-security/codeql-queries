/**
 * @name Weak encryption: Insufficient key size
 * @description Finds uses of encryption algorithms with too small a key size
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @precision high
 * @id cs/insufficient-key-size
 * @tags security
 *       external/cwe/cwe-326
 */

import csharp
import github.crypto

from Crypto::AsymmetricAlgorithms aglms, int key_size
where
  key_size = aglms.getKeySize() and
  key_size > aglms.maxKeySize()
select aglms,
  "Key size " + key_size.toString() + " is to large for algorithm (max: " + aglms.maxKeySize() + ")"
