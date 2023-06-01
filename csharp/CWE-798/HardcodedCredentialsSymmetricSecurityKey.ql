/**
 * @name Hard-coded credentials
 * @description Credentials are hard coded in the source code of the application.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @id cs/hardcoded-credentials-symmetricsecuritykey
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 */

import csharp
private import semmle.code.csharp.frameworks.Moq
private import semmle.code.csharp.frameworks.System
private import semmle.code.csharp.dataflow.TaintTracking
private import DataFlow::PathGraph


/**
 * A data flow source for hard coded credentials.
 */
abstract class Source extends DataFlow::ExprNode { }

/**
 * A data flow sink for hard coded credentials.
 */
abstract class Sink extends DataFlow::ExprNode { }

/**
 * A sanitizer for hard coded credentials.
 */
abstract class Sanitizer extends DataFlow::ExprNode { }

/**
 * A string literal that is not empty, and not an expression placeholder.
 */
class NonEmptyStringLiteral extends Source {
  NonEmptyStringLiteral() {
    exists(StringLiteral literal |
      this.getExpr() = literal
      and literal.getValue().length() > 1
      and literal.fromSource()
      and not literal.getValue().matches("${%}")
    )
  }
}

/**
 * The creation of a literal byte array.
 */
class ByteArrayLiteral extends Source {
  ByteArrayLiteral() {
    this.getExpr() =
      any(ArrayCreation ac |
        ac.getArrayType().getElementType() instanceof ByteType and
        ac.hasInitializer()
      )
    and this.getExpr().fromSource()
  }
}

/**
 * The creation of a literal char array.
 */
class CharArrayLiteral extends Source {
  CharArrayLiteral() {
    this.getExpr() =
      any(ArrayCreation ac |
        ac.getArrayType().getElementType() instanceof CharType and
        ac.hasInitializer()
      )
    and this.getExpr().fromSource()
  }
}

// taint from a string literal to the constructor of a SymmetricSecurityKey
class LiteralToSecurityKeyConfig extends TaintTracking::Configuration {
  LiteralToSecurityKeyConfig() { this = "LiteralToSecurityKeyConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof Source }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof Sink and
    not any(ReturnedByMockObject mock).getAMemberInitializationValue() = sink.asExpr() and
    not any(ReturnedByMockObject mock).getAnArgument() = sink.asExpr()
  }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }
}

class SymmetricSecurityKey extends Sink {
  SymmetricSecurityKey() {
    exists(ObjectCreation securityKey |
      securityKey.getAnArgument() = this.getExpr() and
      securityKey.getType().getQualifiedName() in [
        "Microsoft.IdentityModel.Tokens.SymmetricSecurityKey",
        "System.IdentityModel.Tokens.SymmetricSecurityKey"
      ]
    )
  }
}


/** 
 *  A result from a mock interface
 *  Ignore values that are ultimately returned by mocks, as they don't represent "real" credentials.
*/
class MockSanitizer extends Sanitizer {
  MockSanitizer() {
    exists(ReturnedByMockObject mock|
      mock.getAMemberInitializationValue() = this.asExpr()
      or mock.getAnArgument() = this.asExpr()
    )
  }
}

/**
 * A format argument to `Format`, that is considered not to be a source of hardcoded secret data.
 */
class StringFormatSanitizer extends Sanitizer {
  StringFormatSanitizer() {
    this.getExpr() =
      any(SystemStringClass s).getFormatMethod().getACall().getArgumentForName("format")
  }
}

/**
 * A replacement argument to `Replace`, that is considered not to be a source of hardcoded secret
 * data.
 */
class StringReplaceSanitizer extends Sanitizer {
  StringReplaceSanitizer() {
    exists(SystemStringClass s, Call c | c = s.getReplaceMethod().getACall() |
      this.getExpr() = c.getArgumentForName("newValue") or
      this.getExpr() = c.getArgumentForName("newChar")
    )
  }
}

/**
 * A call to a `ToString()` method, which is considered not to return hard-coded constants.
 */
class ToStringSanitizer extends Sanitizer {
  ToStringSanitizer() { this.getExpr() = any(Call c | c.getTarget().hasName("ToString")) }
}

/**
 * A call to a configuration section or access to configuration data, using the string as a key.
 */
class ConfigurationSanitizer extends Sanitizer {
  ConfigurationSanitizer() {
    exists(PropertyAccess configuration|
      configuration.getType().getQualifiedName() = "Microsoft.Extensions.IConfiguration"
      and configuration.getAChild*() = this.asExpr()
    )
  }
}

// predicate config(PropertyAccess configuration, string name, string qname) {
//   configuration.getType().getName() = name
//   and configuration.getType().getQualifiedName() = qname
// }


from DataFlow::PathNode source, DataFlow::PathNode sink, LiteralToSecurityKeyConfig config
where config.hasFlowPath(source, sink)
select source, sink, source, "Hard-coded credential $@ used as SymmetricSecurityKey $@",
  source.getNode().asExpr(), source.getNode().toString(), sink.getNode().asExpr(), "here"
