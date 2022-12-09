/**
 * @name SQL query built from external parameter (not a known source)
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @sub-severity critical
 * @precision low
 * @id py/sql-injection-external
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a1
 *       external
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.internal.DataFlowPublic
private import semmle.python.dataflow.new.internal.DataFlowDispatchPointsTo
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.types.Builtins
private import semmle.python.dataflow.new.BarrierGuards
private import DataFlow::PathGraph
private import semmle.python.security.dataflow.SqlInjectionCustomizations
private import github.LocalSources

class UnknownExternalInput extends DataFlow::Node {
  UnknownExternalInput() {
    parameterInUnknownExternalFunction(_, this)
    or
    callToUnknownExternalFunction(this)
  }
}

predicate parameterInUnknownExternalFunction(DataFlowCallable function, LocalSourceParameterNode node) {
    node.getEnclosingCallable() = function
    and node.getScope().inSource()
    // check there are no callers to the function
    and not exists(function.getACall())
    and not node instanceof RemoteFlowSource
    and not node instanceof LocalSources::Range
    // and it isn't a method on a Class
    and not function.getScope().getScope() instanceof ClassScope
}

predicate callToUnknownExternalFunction(DataFlow::Node node) {
  exists(CallNode callnode|
    callnode = node.asCfgNode() and
    callnode.getScope().inSource()
    // the target function isn't defined in the source, and it isn't a builtin
    and not exists(CallableValue function|
      callnode = function.getACall()
      and
      (
        function.getScope().inSource()
        or
        function.isBuiltin()
      )
    )
  )
  and not node instanceof RemoteFlowSource
  and not node instanceof LocalSources::Range
}

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
class SQLInjectionConfiguration extends TaintTracking::Configuration {
  SQLInjectionConfiguration() { this = "LocalSQLInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof UnknownExternalInput }

  override predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

from SQLInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
