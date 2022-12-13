/**
 * @name Code injection
 * @description Interpreting unsanitized user input as code allows a malicious user to perform arbitrary
 *              code execution.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @sub-severity critical
 * @precision low
 * @id py/code-injection
 * @tags security
 *       external/owasp/owasp-a1
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-116
 *       local
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import DataFlow::PathGraph
import github.LocalSources
private import semmle.python.security.dataflow.CodeInjectionCustomizations

/**
 * A taint-tracking configuration for detecting code injection vulnerabilities.
 */
class CodeInjectionConfiguration extends TaintTracking::Configuration {
  CodeInjectionConfiguration() { this = "CodeInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

  override predicate isSink(DataFlow::Node sink) { sink instanceof CodeInjection::Sink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof CodeInjection::Sanitizer }
}

from CodeInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "$@ flows to here and is interpreted as code.",
  source.getNode(), "A user-provided value"
