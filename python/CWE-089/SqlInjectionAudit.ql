/**
 * @name SQL query built from user-controlled sources
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision very-low
 * @id py/audit/sql-injection
 * @tags security
 *       external/cwe/cwe-089
 *       audit
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import SqlInjectionHeuristicInst::PathGraph
private import semmle.python.security.dataflow.SqlInjectionCustomizations
//
import github.Utils

/**
 * A taint-tracking configuration for detecting SQL injection vulnerabilities.
 */
module SqlInjectionHeuristicInst = TaintTracking::Global<SqlInjectionHeuristicImpl>;

private module SqlInjectionHeuristicImpl implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof DynamicStrings }

  predicate isSink(DataFlow::Node sink) { sink instanceof SqlInjection::Sink }

  predicate isBarrier(DataFlow::Node node) { node instanceof SqlInjection::Sanitizer }
}

from SqlInjectionHeuristicInst::PathNode source, SqlInjectionHeuristicInst::PathNode sink
where SqlInjectionHeuristicInst::flowPath(source, sink)
select sink.getNode(), source, sink, "This SQL query depends on $@.", source.getNode(),
  "a user-provided value"
