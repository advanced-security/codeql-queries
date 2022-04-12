import csharp

module Crypto {
  class HashingAlgorithm extends DataFlow::ExprNode {
    abstract DataFlow::ExprNode getHashValue();

    abstract DataFlow::ExprNode getSalt();

    abstract DataFlow::ExprNode getIterations();
  }

  class SymmetricAlgorithm extends DataFlow::ExprNode {
    abstract int maxKeySize();

    abstract int minKeySize();

    abstract int getKeySize();
  }

  // Abstraction classes
  abstract class HashingAlgorithms extends HashingAlgorithm { }

  abstract class SymmetricAlgorithms extends SymmetricAlgorithm { }

  // Content
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

  class DSACryptoServiceProvider extends SymmetricAlgorithms {
    DSACryptoServiceProvider() {
      exists(ObjectCreation object |
        object
            .getType()
            .hasQualifiedName("System.Security.Cryptography", "DSACryptoServiceProvider") and
        this.asExpr() = object
      )
    }

    override int maxKeySize() { result = 1024 }

    override int minKeySize() { result = 1024 }

    override int getKeySize() {
      this.asExpr().(ObjectCreation).hasNoArguments() and
      result = 1024
      or
      // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider.-ctor?view=net-6.0#system-security-cryptography-dsacryptoserviceprovider-ctor(system-int32)
      result = this.asExpr().(ObjectCreation).getArgument(0).getValue().toInt()
    }
  }

  class RC2CryptoServiceProvider extends SymmetricAlgorithms {
    RC2CryptoServiceProvider() {
      exists(ObjectCreation object |
        object
            .getType()
            .hasQualifiedName("System.Security.Cryptography", "RC2CryptoServiceProvider") and
        this.asExpr() = object
      )
    }

    override int maxKeySize() { result = 128 }

    override int minKeySize() { result = 128 }

    override int getKeySize() {
      this.asExpr().(ObjectCreation).hasNoArguments() and
      result = 128 // default
      or
      // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider.-ctor?view=net-6.0#system-security-cryptography-dsacryptoserviceprovider-ctor(system-int32)
      result = this.asExpr().(ObjectCreation).getArgument(0).getValue().toInt()
    }
  }

  class RSA extends SymmetricAlgorithms {
    RSA() {
      exists(ObjectCreation object |
        object
            .getType()
            .hasQualifiedName("System.Security.Cryptography", ["RSACryptoServiceProvider", "RSACng"]) and
        this.asExpr() = object
      )
      or
      exists(MethodCall call |
        call.getType().hasQualifiedName("System.Security.Cryptography", ["RSA"]) and
        call.getTarget().hasName("Create") and
        this.asExpr() = call
      )
    }

    override int maxKeySize() { result = 2048 }

    override int minKeySize() { result = 2048 }

    override int getKeySize() {
      (
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.dsacryptoserviceprovider.-ctor?view=net-6.0#system-security-cryptography-dsacryptoserviceprovider-ctor(system-int32)
        this.asExpr().(ObjectCreation).hasNoArguments() and
        result = 1024
        or
        result = this.asExpr().(ObjectCreation).getArgument(0).getValue().toInt()
      )
      or
      (
        // https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsa.create?view=net-6.0#system-security-cryptography-rsa-create(system-int32)
        this.asExpr().(MethodCall).hasNoArguments() and
        result = 1024
        or
        result = this.asExpr().(MethodCall).getArgument(0).getValue().toInt()
      )
    }
  }
}
