/**
 * @name Resolving XML external entity in user-controlled data
 * @description Parsing user-controlled XML data and allowing expansion of external entity
 * references may lead to disclosure of confidential data or denial of service.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.0
 * @precision high
 * @id python/xxe-local-string-taint
 * @tags security
 *       external/cwe/cwe-611
 *       external/cwe/cwe-776
 *       external/cwe/cwe-827
 */

private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import DataFlow::PathGraph
private import XXELocalLib

from DataFlow::PathNode source, DataFlow::PathNode sink
where any(XxeStringConfig conf).hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Unsafe parsing of XML from local $@.", source.getNode(),
  "user input"
