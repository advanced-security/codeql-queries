/**
 * @name Partial Path Query from Sink
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id py/debugging/partial-path-from-sink
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

// Manual Sinks
class ManualSinks extends DataFlow::Node {
  ManualSinks() { this = API::moduleImport("any").getMember("any").getACall() }
}

// Partial Graph
module RemoteFlowsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { none() }

  predicate isSink(DataFlow::Node sink) {
    // Dangerous Sinks
    dangerousSinks(sink)
    or
    // Manual Sinks
    sink instanceof ManualSinks
  }
}

int explorationLimit() { result = 10 }

module RemoteFlows = DataFlow::Global<RemoteFlowsConfig>;

module RemoteFlowsPartial = RemoteFlows::FlowExploration<explorationLimit/0>;

import RemoteFlowsPartial::PartialPathGraph

from RemoteFlowsPartial::PartialPathNode source, RemoteFlowsPartial::PartialPathNode sink
where RemoteFlowsPartial::partialFlowRev(source, sink, _)
/// Filter by location
// and findByLocation(source.getNode(), "app.py", 20)
//
/// Filter by Function Parameters
// and functionParameters(source.getNode())
//
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
