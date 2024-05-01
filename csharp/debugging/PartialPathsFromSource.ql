/**
 * @name Partial Path Query from Source
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 1.0
 * @sub-severity low
 * @precision low
 * @id csharp/debugging/partial-path-from-source
 * @tags debugging
 */

import csharp
import semmle.code.csharp.dataflow.TaintTracking
import semmle.code.csharp.dataflow.DataFlow
import semmle.code.csharp.security.dataflow.flowsources.Remote
import semmle.code.csharp.security.dataflow.flowsources.Local

//Specific
import semmle.code.csharp.security.dataflow.UnsafeDeserializationQuery

// Partial Graph
module RemoteFlowsConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    // source instanceof RemoteFlowSource
    // or
    // source instanceof LocalFlowSource
    // or
    // Deserialization Sources (how do we make this more specific?)
    source instanceof Source
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
// and findByLocation(sink.getNode(), "app.cs", 20)
//
/// Filter by Function Parameters
// and functionParameters(sink.getNode())
//
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
