/**
 * @name Partial Path Query
 * @description Partial Path Query
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @precision high
 * @sub-severity high
 * @id py/debugging/partial-sql-injection
 * @tags debugging
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import DataFlow::PartialPathGraph
import semmle.python.ApiGraphs
// Helpers
import github.Helpers
import github.LocalSources
// Bring in the CommandInjection config
private import semmle.python.security.dataflow.CommandInjectionCustomizations

// Parcial Graph
class RemoteFlows extends TaintTracking::Configuration {
  RemoteFlows() { this = "Partial Paths from Source" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource or source instanceof LocalSources::Range
  }

  override int explorationLimit() { result = 10 }
}

from RemoteFlows config, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
where config.hasPartialFlow(source, sink, _)
// and findByLocation(source, "relative/source/path.py", 10)
// and findByLocation(sink, "relative/sink/path.py", 10)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
