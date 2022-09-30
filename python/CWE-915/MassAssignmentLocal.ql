/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision high
 * @sub-severity high
 * @id py/mass-assignment
 * @tags security
 *       external/cwe/cwe-2915
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import DataFlow::PathGraph
// New libs
import github.MassAssignment
import github.LocalSources

class MassAssignmentConfig extends TaintTracking::Configuration {
  MassAssignmentConfig() { this = "Mass Assignment Config" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

  override predicate isSink(DataFlow::Node sink) { sink instanceof MassAssignment::Sinks }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof MassAssignment::Sanitizer }
}

from MassAssignmentConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
