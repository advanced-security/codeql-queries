/**
 * Contains customizations to the standard library.
 *
 * This module is imported by `java.qll`, so any customizations defined here automatically
 * apply to all queries.
 *
 * Typical examples of customizations include adding new subclasses of abstract classes such as
 * the `RemoteFlowSource` and `AdditionalTaintStep` classes associated with the security queries
 * to model frameworks that are not covered by the standard library.
 */

import java
import semmle.code.java.dataflow.FlowSteps
// SQL sinks
// import semmle.code.java.security.QueryInjection
import semmle.code.java.security.XSS


class WebgoatSink extends XssSink {
WebgoatSink() {
  this.asExpr()
  .(Argument)
  .getCall()
  .getCallee()
  .hasQualifiedName("org.owasp.webgoat.assignments", "AttackResult$AttackResultBuilder",
  ["output", "outputArgs", "feedback", "feedbackArgs"])
}}
/// Missing Sinks
// ==============================
/**
//commenting this out till fix to SqlExpr is found. 

class ExtendedSQLSinks extends QueryInjectionSink {
  ExtendedSQLSinks() {
    this.asExpr() instanceof SqlExpr
    or
    exists(MethodAccess ma |
      ma.getMethod().getDeclaringType().hasQualifiedName("com.azure.cosmos", "CosmosContainer") and
      ma.getMethod().hasName("queryItems") and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

/// Missing taintstep's
// ==============================
// File() `getName` Method contains taints data
class PreserveGetName extends TaintPreservingCallable {
  // new File(TAINT).getName()
  PreserveGetName() { this.getName() = "getName" }

  override predicate returnsTaintFrom(int arg) { arg = -1 }
}
*/