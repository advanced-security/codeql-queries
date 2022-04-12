import csharp

module Crypto {
  class HashingAlgorithm extends DataFlow::ExprNode {
    abstract DataFlow::ExprNode getHashValue();

    abstract DataFlow::ExprNode getSalt();

    abstract DataFlow::ExprNode getIterations();
  }

  abstract class HashingAlgorithms extends HashingAlgorithm { }

  class CryptoRfc2898DeriveBytes extends HashingAlgorithms {
    CryptoRfc2898DeriveBytes() {
      exists(ObjectCreation object |
        object.getType().getQualifiedName() = "System.Security.Cryptography.Rfc2898DeriveBytes" and
        this.asExpr() = object
      )
    }

    override DataFlow::ExprNode getHashValue() {
      result.asExpr() = this.asExpr().(ObjectCreation).getArgument(0)
    }

    override DataFlow::ExprNode getSalt() {
      result.asExpr() = this.asExpr().(ObjectCreation).getArgument(1)
    }

    override DataFlow::ExprNode getIterations() {
      result.asExpr() = this.asExpr().(ObjectCreation).getArgument(2)
    }
  }
}
