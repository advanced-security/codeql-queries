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
import SQLInjectionConfigurationInst::PathGraph
import github.LocalSources
private import semmle.python.security.dataflow.SqlInjectionCustomizations

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
module SQLInjectionConfigurationInst = TaintTracking::Global<SQLInjectionConfigurationImpl>;

private module SQLInjectionConfigurationImpl implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof LocalSources::Range }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

from SQLInjectionConfigurationInst::PathNode source, SQLInjectionConfigurationInst::PathNode sink
where SQLInjectionConfigurationInst::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
