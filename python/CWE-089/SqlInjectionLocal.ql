/**
 * @name SQL query built from user-controlled sources
 * @description Building a SQL query from user-controlled sources is vulnerable to insertion of
 *              malicious SQL code by the user.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 10.0
 * @sub-severity critical
 * @precision low
 * @id py/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a1
 *       local
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.BarrierGuards
import DataFlow::PathGraph
import github.LocalSources

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
class SQLInjectionConfiguration extends TaintTracking::Configuration {
  SQLInjectionConfiguration() { this = "LocalSQLInjectionConfiguration" }

  override predicate isSource(DataFlow::Node source) { source instanceof LocalSources }

  override predicate isSink(DataFlow::Node sink) { sink = any(SqlExecution e).getSql() }

  override predicate isSanitizerGuard(DataFlow::BarrierGuard guard) {
    guard instanceof StringConstCompare
  }
}

from SQLInjectionConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
