/**
 * @name Hardcoded Salt
 * @description Hardcoded Salt
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision medium
 * @id cs/hardcoded-salt
 * @tags security
 *       external/cwe/cwe-760
 */

import csharp
private import semmle.code.csharp.frameworks.Moq
private import semmle.code.csharp.dataflow.DataFlow::DataFlow::PathGraph
// import semmle.code.csharp.frameworks.system.security.Cryptography
private import github.hardcoded
private import github.crypto

module HardcodedSalt {
  abstract class Source extends DataFlow::ExprNode { }

  abstract class Sink extends DataFlow::ExprNode { }

  abstract class Sanitizer extends DataFlow::ExprNode { }

  abstract class SanitizerGuard extends DataFlow::BarrierGuard { }

  /*
   * Sources
   */

  class Hardcoded extends Source {
    Hardcoded() { this instanceof HardcodedValues }
  }

  /*
   * Sinks
   */

  class HashAlgSalts extends Sink {
    HashAlgSalts() { exists(Crypto::HashingAlgorithms hash | this = hash.getSalt()) }
  }

  /*
   * Config
   */

  class TaintTrackingConfiguration extends TaintTracking::Configuration {
    TaintTrackingConfiguration() { this = "HardcodedSalt" }

    override predicate isSource(DataFlow::Node source) { source instanceof HardcodedSalt::Source }

    override predicate isSink(DataFlow::Node sink) {
      sink instanceof HardcodedSalt::Sink and
      not any(ReturnedByMockObject mock).getAMemberInitializationValue() = sink.asExpr() and
      not any(ReturnedByMockObject mock).getAnArgument() = sink.asExpr()
    }

    override predicate isSanitizer(DataFlow::Node node) { node instanceof Sanitizer }

    override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
      guard instanceof SanitizerGuard
    }
  }
}

from
  HardcodedSalt::TaintTrackingConfiguration config, DataFlow::PathNode source,
  DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "hardcoded salt"
