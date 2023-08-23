/**
 * @name Deserializing untrusted input
 * @description Deserializing user-controlled data may allow attackers to execute arbitrary code.
 * @kind path-problem
 * @id py/unsafe-deserialization
 * @problem.severity error
 * @security-severity 8.0
 * @sub-severity high
 * @precision low
 * @tags external/cwe/cwe-502
 *       security
 *       serialization
 *       local
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import UnsafeDeserializationConfigurationInst::PathGraph
// Extending library
import semmle.python.security.dataflow.UnsafeDeserializationCustomizations
// Internal library
import github.LocalSources

/**
 * A taint-tracking configuration for detecting arbitrary code execution
 * vulnerabilities due to deserializing user-controlled data.
 */
module UnsafeDeserializationConfigurationInst =
  TaintTracking::Global<UnsafeDeserializationConfigurationImpl>;

private module UnsafeDeserializationConfigurationImpl implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

  predicate isSink(DataFlow::Node sink) { sink instanceof UnsafeDeserialization::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof UnsafeDeserialization::Sanitizer }
}

from
  UnsafeDeserializationConfigurationInst::PathNode source,
  UnsafeDeserializationConfigurationInst::PathNode sink
where UnsafeDeserializationConfigurationInst::flowPath(source, sink)
select sink.getNode(), source, sink, "Deserializing of $@.", source.getNode(), "untrusted input"
