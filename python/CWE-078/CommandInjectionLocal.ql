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
//import DataFlow::PathGraph
import github.LocalSources
private import semmle.python.security.dataflow.CommandInjectionCustomizations

private module CommandInjectionConfiguration implements DataFlow::ConfigSig{ 

  predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

  predicate isSink(DataFlow::Node sink) { sink instanceof CommandInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof CommandInjection::Sanitizer }
}

module CommandInjectionFlows = DataFlow::Global<CommandInjectionConfiguration>;
import CommandInjectionFlows::PathGraph //importing the path graph from the module

from CommandInjectionFlows::PathNode source, CommandInjectionFlows::PathNode sink //Using PathNode from the module
where CommandInjectionFlows::flowPath(source, sink) //using flowPath instead of hasFlowPath
select sink.getNode(), source, sink, "This command depend son $@.", source.getNode(), "a user-provided value"