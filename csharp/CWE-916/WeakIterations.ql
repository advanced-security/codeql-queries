/**
 * @name Use of Password Hash With Insufficient Computational Effort
 * @description Use of Password Hash With Insufficient Computational Effort
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 4.0
 * @precision medium
 * @id cs/weak-interations
 * @tags security
 *       external/cwe/cwe-916
 */

import csharp
private import semmle.code.csharp.frameworks.Moq
private import semmle.code.csharp.dataflow.DataFlow::DataFlow::PathGraph
// import semmle.code.csharp.frameworks.system.security.Cryptography
private import github.hardcoded
private import github.crypto

module WeakIterations {
  abstract class Source extends DataFlow::ExprNode { }

  abstract class Sink extends DataFlow::ExprNode { }

  abstract class Sanitizer extends DataFlow::ExprNode { }

  abstract class SanitizerGuard extends DataFlow::BarrierGuard { }

  /*
   * Sources
   */

  class Hardcoded extends Source {
    Hardcoded() { this.getExpr().(IntLiteral).getValue().toInt() < 1000 }
  }

  /*
   * Sinks
   */

  class HashAlgSalts extends Sink {
    HashAlgSalts() { exists(Crypto::HashingAlgorithms hash | this = hash.getIterations()) }
  }

  /*
   * Config
   */

  class TaintTrackingConfiguration extends TaintTracking::Configuration {
    TaintTrackingConfiguration() { this = "WeakInteractions" }

    override predicate isSource(DataFlow::Node source) { source instanceof WeakIterations::Source }

    override predicate isSink(DataFlow::Node sink) {
      sink instanceof WeakIterations::Sink and
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
  WeakIterations::TaintTrackingConfiguration config, DataFlow::PathNode source,
  DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "hardcoded weak iterations"
