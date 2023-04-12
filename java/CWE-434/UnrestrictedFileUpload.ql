/**
 * @name Unrestricted Upload of File with Dangerous Type
 * @description Unrestricted Upload of File with Dangerous Type
 * @id java/unrestricted-file-upload
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @tags security
 *       external/cwe/cwe-434
 */

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.dataflow.TaintTracking2
// Models as Data
private import semmle.code.java.dataflow.ExternalFlow

abstract class FileWriteSinks extends DataFlow::Node { }

class General extends FileWriteSinks {
  General() {
    exists(MethodAccess ma |
      // https://docs.oracle.com/javase/7/docs/api/java/nio/file/Files.html#copy(java.io.InputStream,%20java.nio.file.Path,%20java.nio.file.CopyOption...)
      ma.getMethod().hasQualifiedName("java.nio.file", "Files", "copy") and
      ma.getArgument(0) = this.asExpr()
      or
      // https://docs.oracle.com/javase/7/docs/api/java/io/OutputStream.html
      ma.getMethod().hasQualifiedName("java.io", "OutputStream", "write") and
      ma.getArgument(0) = this.asExpr()
    )
  }
}

class UnrestrictedFileUploadConfig extends TaintTracking::Configuration {
  UnrestrictedFileUploadConfig() { this = "UnrestrictedFileUploadConfig" }

  override predicate isSource(DataFlow::Node node) { node instanceof RemoteFlowSource }

  override predicate isSink(DataFlow::Node node) {
    sinkNode(node, "write-file")
    or
    node instanceof FileWriteSinks
  }
}

from UnrestrictedFileUploadConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unrestricted upload $@.", source.getNode(),
  "user-provided content"
