/**
 * @name Cross-site scripting
 * @description Writing user input directly to a web page
 *              allows for a cross-site scripting vulnerability.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id java/xss
 * @tags security
 *       external/cwe/cwe-079
 */

import java
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.XSS
import DataFlow::PathGraph

private class CustomXSSSanitizer extends XssSanitizer {
  CustomXSSSanitizer() {
    exists(MethodAccess ma |
      // Namespace + Object/Class
      ma.getMethod().getDeclaringType().hasQualifiedName("org.example", "Santitizes") and
      (
        // Sanitizer methods
        ma.getMethod().getName() = "escapeHtml" or
        ma.getMethod().getName() = "escapeJavaScript"
      ) and
      this.asExpr() = ma
    )
  }
}

class XSSConfig extends TaintTracking::Configuration {
  XSSConfig() { this = "XSSConfig" }

  override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node sink) { sink instanceof XssSink }

  // Add our custom sanitizer class in the configuration
  override predicate isSanitizer(DataFlow::Node node) { node instanceof CustomXSSSanitizer }

  override predicate isSanitizerOut(DataFlow::Node node) { node instanceof XssSinkBarrier }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    any(XssAdditionalTaintStep s).step(node1, node2)
  }
}

from DataFlow::PathNode source, DataFlow::PathNode sink, XSSConfig conf
where conf.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to $@.",
  source.getNode(), "user-provided value"
