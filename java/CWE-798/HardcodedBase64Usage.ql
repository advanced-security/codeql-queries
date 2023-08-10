/**
 * @name Base64 Hardcoded Password
 * @description Static hardcoded base64 password / key
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision low
 * @sub-severity high
 * @id java/hardcoded-password
 * @tags security
 *       external/cwe/cwe-798
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
//import DataFlow::PathGraph
// Internal
import github.Encoding
import github.Hardcoded

private module HardcodedBase64Usage implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Hardcoded }

  predicate isSink(DataFlow::Node sink) { sink instanceof Base64::Decoding }
}

module HardcodedBase64Flows = DataFlow::Global<HardcodedBase64Usage>;
import HardcodedBase64Flows::PathGraph //importing the path graph from the module

from HardcodedBase64Flows::PathNode source, HardcodedBase64Flows::PathNode sink //Using PathNode from the module
where HardcodedBase64Flows::flowPath(source, sink) //using flowPath instead of hasFlowPath
select sink.getNode(), source, sink, "Sensitive data is being logged $@.", source.getNode(),
  "user-provided value"