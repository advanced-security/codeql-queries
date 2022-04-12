/**
 * @name Weak encryption: Insufficient key size
 * @description Finds uses of encryption algorithms with too small a key size
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.5
 * @precision high
 * @id cs/encryption-keysize-use-getter
 * @tags security
 *       external/cwe/cwe-326
 */

import csharp
import github.crypto

from Crypto::SymmetricAlgorithms aglms, PropertyAccess props, Expr expr
where
  aglms.getType().hasName(["DSACryptoServiceProvider", "RSACryptoServiceProvider"]) and
  props.getTarget().getDeclaringType() = aglms.getType() and
  props.getTarget().getName() = "KeySize" and
  expr = props.getParent().(Assignment).getRValue()
select expr, "Cannot use Getter to set key size"
