/**
 * @name Weak encryption: Key size set using a Getter and failing to set key size
 * @description Finds uses of encryption algorithms using a Getter and not setting the size of the key
 * @kind problem
 * @problem.severity warning
 * @security-severity 1.0
 * @precision high
 * @id cs/encryption-keysize-use-getter
 * @tags security
 *       external/cwe/cwe-326
 */

import csharp
import github.crypto

from Crypto::AsymmetricAlgorithms aglms, PropertyAccess props, Expr expr
where
  aglms.getType().hasName(["DSACryptoServiceProvider", "RSACryptoServiceProvider"]) and
  props.getTarget().getDeclaringType() = aglms.getType() and
  props.getTarget().getName() = "KeySize" and
  expr = props.getParent().(Assignment).getRValue()
select expr, "Cannot use Getter to set key size"
