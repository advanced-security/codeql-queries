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
import semmle.python.ApiGraphs
// Helpers
import github.Helpers
import github.LocalSources

// Partial Graph
module RemoteFlowsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource
    or
    source instanceof LocalSources::Range
  }

  predicate isSink(DataFlow::Node sink) { none() }
}

int explorationLimit() { result = 10 }

module RemoteFlows = DataFlow::Global<RemoteFlowsConfig>;

module RemoteFlowsPartial = RemoteFlows::FlowExploration<explorationLimit/0>;

import RemoteFlowsPartial::PartialPathGraph

from RemoteFlowsPartial::PartialPathNode source, RemoteFlowsPartial::PartialPathNode sink
where RemoteFlowsPartial::partialFlow(source, sink, _)
/// Filter by location
// and findByLocation(sink.getNode(), "app.py", 20)
//
/// Filter by Function Parameters
// and functionParameters(sink.getNode())
//
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
