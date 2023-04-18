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
// Bring in the CommandInjection config
private import semmle.python.security.dataflow.CommandInjectionCustomizations

// Partial Graph
module RemoteFlowsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    source instanceof CommandInjection::Source or source instanceof LocalSources::Range
  }

  // We need to provide `isSink`
  predicate isSink(DataFlow::Node sink) { sink instanceof CommandInjection::Sink }
}

int explorationLimit() { result = 10 }

module RemoteFlows = DataFlow::Global<RemoteFlowsConfig>;

module RemoteFlowsPartial = RemoteFlows::FlowExploration<explorationLimit/0>;

import RemoteFlowsPartial::PartialPathGraph

from RemoteFlowsPartial::PartialPathNode source, RemoteFlowsPartial::PartialPathNode sink
where RemoteFlowsPartial::partialFlow(source, sink, _)
// and findByLocation(source, "relative/source/path.py", 10)
// and findByLocation(sink, "relative/sink/path.py", 10)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
