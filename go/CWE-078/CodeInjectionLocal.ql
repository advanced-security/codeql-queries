/**
 * @name Command built from user-controlled sources
 * @description Building a system command from user-controlled sources is vulnerable to insertion of
 *              malicious code by the user.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 4.0
 * @precision low
 * @id go/command-injection
 * @tags security
 *       external/cwe/cwe-078
 *       local
 */

import go
import semmle.go.security.CommandInjection
import DataFlow::PathGraph
import semmle.go.security.CommandInjectionCustomizations::CommandInjection
import github.LocalSources

class CommandInjectionLocalConfiguration extends TaintTracking::Configuration {
  CommandInjectionLocalConfiguration() { this = "CommandInjection" }

  // Local sources of input
  override predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Sources }

  override predicate isSink(DataFlow::Node sink) {
    exists(Sink s | sink = s | not s.doubleDashIsSanitizing())
  }

  override predicate isSanitizer(DataFlow::Node node) {
    super.isSanitizer(node) or
    node instanceof Sanitizer
  }

  override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
    guard instanceof SanitizerGuard
  }
}

// TODO: DoubleDashSanitizingConfiguration?
from CommandInjectionLocalConfiguration cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on $@.", source.getNode(),
  "a user-provided value"
