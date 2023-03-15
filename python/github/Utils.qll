import python
private import semmle.python.ApiGraphs
private import semmle.python.Concepts
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.internal.TaintTrackingPrivate

// List of all the format strings
// - python/ql/lib/semmle/python/dataflow/new/internal/TaintTrackingPrivate.qll
class DynamicStrings extends DataFlow::Node {
  DynamicStrings() {
    (
      // s = f"WHERE name = '{input}'"
      exists(Fstring fmtstr | this.asExpr() = fmtstr)
      or
      // "SELECT * FROM users WHERE username = '{}'".format(username)
      exists(CallNode format, string methods, ControlFlowNode object |
        object = format.getFunction().(AttrNode).getObject(methods)
      |
        methods = "format" and
        this.asExpr() = format.getNode()
      )
      or
      // q = "WHERE name = %s" % username
      exists(BinaryExpr expr |
        expr.getOp() instanceof Mod and
        expr.getLeft().getParent() = this.asExpr()
      )
    ) and
    this.getScope().inSource()
  }
}
