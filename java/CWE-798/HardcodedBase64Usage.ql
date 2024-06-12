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
//import DataFlow::PathGraph0
// Internal
import github.Encoding
import github.Hardcoded

module HardcodedPasswordBase64Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof Hardcoded }

  predicate isSink(DataFlow::Node sink) { sink instanceof Base64::Decoding}

  predicate isBarrier(DataFlow::Node node) {
    exists(Type t | t = node.getType() | t instanceof BoxedType or t instanceof PrimitiveType)
  }
}

module HardcodedPasswordBase64Flow = TaintTracking::Global<HardcodedPasswordBase64Config>;
import HardcodedPasswordBase64Flow::PathGraph //importing the path graph from the module

// ========== Query ==========
from HardcodedPasswordBase64Flow::PathNode source, HardcodedPasswordBase64Flow::PathNode sink //Using PathNode from the module
where HardcodedPasswordBase64Flow::flowPath(source, sink) //using flowPath instead of hasFlowPath
select sink.getNode(), source, "Sensitive data is being logged $@.", source.getNode()