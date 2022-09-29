/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
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

class MassAssignment extends DataFlow::Node {
  MassAssignment() {
    // Usage of the build it `setattr(obj, SINK, value)`
    this = API::builtin("setattr").getACall().getArg(1)
    or
    // Unlikely but
    // class.__setattr__(SINK, value)
    exists(Call call |
      call.toString() = ["__setattr__"] and
      this.asExpr() = call.getArg(0)
    )
  }
}

class MassAssignmentConfig extends TaintTracking::Configuration {
  MassAssignmentConfig() { this = "Mass Assignment Config" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource::Range }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof MassAssignment and sink.getScope().inSource()
  }
}

from MassAssignmentConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
