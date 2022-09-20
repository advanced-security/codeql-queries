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
import github.Base64

class HardcodedPasswordBase64 extends DataFlow::Configuration {
  HardcodedPasswordBase64() { this = "HardcodedPasswordBase64" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof HardcodedExpr and
    not source.asExpr().getEnclosingCallable() instanceof ToStringMethod
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof Base64::Decoding }

  override predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // String.getBytes()
    node1.asExpr().getType() instanceof TypeString and
    exists(MethodAccess ma | ma.getMethod().hasName(["getBytes", "toCharArray"]) |
      node2.asExpr() = ma and
      ma.getQualifier() = node1.asExpr()
    )
    or
    // byte[].toString()
    node1.asExpr().getType() instanceof Array and
    exists(MethodAccess ma | ma.getMethod().hasName(["toString"]) |
      node2.asExpr() = ma and
      ma.getQualifier() = node1.asExpr()
    )
  }
}

// ========== Query ==========
from DataFlow::PathNode source, DataFlow::PathNode sink, HardcodedPasswordBase64 config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Sensative data is being logged $@.", source.getNode(),
  "user-provided value"
