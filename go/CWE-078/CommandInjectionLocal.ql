/**
 * @name Log entries created from user input
 * @description Building log entries from user-controlled sources is vulnerable to
 *              insertion of forged log entries by a malicious user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.8
 * @precision high
 * @id go/local-command-injection
 * @tags security
 *       external/cwe/cwe-078
 */

import go
import DataFlow::PathGraph
import semmle.go.security.CommandInjectionCustomizations
// Internal
import github.LocalSources

class LocalConfiguration extends TaintTracking::Configuration {
  LocalConfiguration() { this = "LocalCommandInjection" }

  override predicate isSource(DataFlow::Node source) { source instanceof CommandInjection::Source }

  override predicate isSink(DataFlow::Node sink) {
    exists(CommandInjection::Sink s | sink = s | not s.doubleDashIsSanitizing())
  }

  override predicate isSanitizer(DataFlow::Node node) {
    super.isSanitizer(node) or
    node instanceof CommandInjection::Sanitizer
  }

  deprecated override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
    guard instanceof CommandInjection::SanitizerGuard
  }
}

from LocalConfiguration c, DataFlow::PathNode source, DataFlow::PathNode sink
where c.hasFlowPath(source, sink)
select sink, source, sink, "This log write receives unsanitized user input from $@.",
  source.getNode(), "here"
