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
import DataFlow::PathGraph
import semmle.code.java.security.HardcodedCredentials
// Internal
import github.Encoding

class HardcodedPasswordBase64 extends TaintTracking::Configuration {
  HardcodedPasswordBase64() { this = "HardcodedPasswordBase64" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof HardcodedExpr and
    not source.asExpr().getEnclosingCallable() instanceof ToStringMethod
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Base64::Decoding }
}

// ========== Query ==========
from DataFlow::PathNode source, DataFlow::PathNode sink, HardcodedPasswordBase64 config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Sensative data is being logged $@.", source.getNode(),
  "user-provided value"
