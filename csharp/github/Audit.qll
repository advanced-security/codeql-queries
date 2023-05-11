private import semmle.code.csharp.dataflow.DataFlow::DataFlow::PathGraph
private import semmle.code.csharp.dataflow.ExternalFlow

class AuditSinks extends DataFlow::Node {
  AuditSinks() { sinkNode(this, "audit") }
}
