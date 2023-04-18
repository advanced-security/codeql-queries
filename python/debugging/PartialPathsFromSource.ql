/**
 * @name Partial Path Query from Source
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id py/debugging/partial-path-from-source
 * @tags debugging
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.dataflow.new.DataFlow::DataFlow::PartialPathGraph
import semmle.python.ApiGraphs
// Helpers
import github.Helpers
import github.LocalSources
// Bring in the CommandInjection config
private import semmle.python.security.dataflow.CommandInjectionCustomizations

// Partial Graph
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
