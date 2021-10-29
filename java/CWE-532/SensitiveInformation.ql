/**
 * @name Sensitive information exposure through logging
 * @description Sensitive information exposure through logging
 * @kind path-problem
 * @id java/sensitive-information-logging
 * @problem.severity warning
 * @security-severity 8.0
 * @precision medium
 * @tags security
 *       gdpr
 *       external/cwe/cwe-532
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
import DataFlow::PathGraph
// Internal
import github.Logging
import github.SensitiveInformation

class SensitiveInformationLoggingConfig extends TaintTracking::Configuration {
  SensitiveInformationLoggingConfig() { this = "SensitiveInformationLoggingConfig" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof SensitiveInformationSources
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof LoggingMethodsSinks }
}

// ========== Query ==========
from DataFlow::PathNode source, DataFlow::PathNode sink, SensitiveInformationLoggingConfig config
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Sensative data is being logged $@.", source.getNode(),
  "user-provided value"
