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
import DataFlow::PathGraph
// Extending library
import semmle.python.security.dataflow.UnsafeDeserializationCustomizations
// Internal library
import github.LocalSources

// https://github.com/github/codeql/blob/main/python/ql/lib/semmle/python/security/injection/Pickle.qll
class CustomUnsafeDeserializationSinks extends UnsafeDeserialization::Sink {
  CustomUnsafeDeserializationSinks() {
    exists(DataFlow::Node call |
      (
        // https://docs.python.org/3/library/pickle.html#pickle.load
        // https://github.com/github/codeql/blob/main/python/ql/lib/semmle/python/security/injection/Pickle.qll
        call = API::moduleImport("pickle").getMember("load").getACall()
        or
        // https://docs.python.org/3/library/marshal.html#marshal.load
        // https://github.com/github/codeql/blob/main/python/ql/lib/semmle/python/security/injection/Marshal.qll
        call = API::moduleImport("marshal").getMember("load").getACall()
        or
        // https://docs.python.org/3/library/shelve.html#shelve.open
        call = API::moduleImport("shelve").getMember("open").getACall()
      ) and
      this = call
    )
  }
}

/**
 * A taint-tracking configuration for detecting arbitrary code execution
 * vulnerabilities due to deserializing user-controlled data.
 */
class UnsafeDeserializationConfiguration extends TaintTracking::Configuration {
  UnsafeDeserializationConfiguration() { this = "UnsafeDeserializationConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalSources }

  override predicate isSink(DataFlow::Node sink) {
    exists(Decoding d |
      d.mayExecuteInput() and
      sink = d.getAnInput()
    )
  }

  override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
    guard instanceof StringConstCompare
  }
}

from UnsafeDeserializationConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Deserializing of $@.", source.getNode(), "untrusted input"
