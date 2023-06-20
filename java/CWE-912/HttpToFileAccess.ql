/**
 * @name Network data written to file
 * @description Writing network data directly to the file system allows arbitrary file upload and might indicate a backdoor.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.3
 * @precision medium
 * @id java/http-to-file-access
 * @tags security
 *       external/cwe/cwe-912
 *       external/cwe/cwe-434
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
// Models as Data
private import semmle.code.java.dataflow.ExternalFlow
// internal
import github.LocalSources


class HttpToFileAccessConfig extends TaintTracking::Configuration {
  HttpToFileAccessConfig() { this = "HttpToFileAccess" }

  override predicate isSource(DataFlow::Node node) { node instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node node) {
    sinkNode(node, "write-file")
    or
    node instanceof FileWriteAccess
  }
}

from HttpToFileAccessConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unrestricted upload $@.", source.getNode(),
  "user-provided content"
