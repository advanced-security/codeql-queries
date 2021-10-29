/**
 * @name Uncontrolled command line
 * @description Using externally controlled strings in a command line may allow a malicious
 *              user to change the meaning of the command.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @sub-severity critical
 * @precision low
 * @id py/command-line-injection
 * @tags security
 *       external/cwe/cwe-078
 *       external/cwe/cwe-088
 *       external/owasp/owasp-a1
 *       local
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import DataFlow::PathGraph
import github.LocalSources

// ========== Configuration ==========
class CommandInjectionConfiguration extends TaintTracking::Configuration {
  CommandInjectionConfiguration() { this = "LocalCommandInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalSources }

  override predicate isSink(DataFlow::Node sink) {
    sink = any(SystemCommandExecution e).getCommand() and
    not sink.getScope().getEnclosingModule().getName() in ["os", "subprocess", "platform", "popen2"]
  }

  override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
    guard instanceof StringConstCompare
  }
}

from CommandInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This command depends on $@.", source.getNode(),
  "a user-provided value"
