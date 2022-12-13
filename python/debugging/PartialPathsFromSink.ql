/**
 * @name Partial Path Query from Sink
 * @kind path-problem
 * @id py/debugging/partial-path-from-sink
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
// Import Sinks
private import semmle.python.security.dataflow.CommandInjectionCustomizations
private import semmle.python.security.dataflow.CodeInjectionCustomizations
private import semmle.python.security.dataflow.ServerSideRequestForgeryCustomizations
private import semmle.python.security.dataflow.SqlInjectionCustomizations
private import semmle.python.security.dataflow.UnsafeDeserializationCustomizations
// Fields Sinks
private import github.HardcodedSecretSinks
private import github.MassAssignment

// Manual Sinks
class ManualSinks extends DataFlow::Node {
  ManualSinks() { this = API::moduleImport("any").getMember("any").getACall() }
}

// Partial Graph
class RemoteFlows extends TaintTracking::Configuration {
  RemoteFlows() { this = "Partial Paths from Sinks" }

  override predicate isSink(DataFlow::Node sink) {
    sink instanceof CommandInjection::Sink or
    sink instanceof CodeInjection::Sink or
    sink instanceof ServerSideRequestForgery::Sink or
    sink instanceof SqlInjection::Sink or
    sink instanceof UnsafeDeserialization::Sink or
    // Fields Query Addtional Sinks
    sink instanceof CredentialSink or
    sink instanceof MassAssignment::Sinks or
    // Add Manual Sinks
    sink instanceof ManualSinks
  }

  override int explorationLimit() { result = 10 }
}

from RemoteFlows config, DataFlow::PartialPathNode source, DataFlow::PartialPathNode sink
where config.hasPartialFlowRev(source, sink, _)
// and findByLocation(source, "relative/source/path.py", 10)
// and findByLocation(sink, "relative/sink/path.py", 10)
select sink.getNode(), source, sink, "Partial Graph $@.", source.getNode(), "user-provided value"
