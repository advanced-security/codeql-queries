/**
 * @name XML External Entity (XXE)
 * @description XXE using file / string from remote sources
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @sub-severity high
 * @precision high
 * @id py/xxe
 * @tags security
 *       external/cwe/cwe-611
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.ApiGraphs
import DataFlow::PathGraph
import github.XXE

class XXEConfiguration extends TaintTracking::Configuration {
  XXEConfiguration() { this = "XXE" }

  override predicate isSource(DataFlow::Node source) { source instanceof XXE::Source }

  override predicate isSink(DataFlow::Node sink) { sink instanceof XXE::Sink }

  override predicate isSanitizer(DataFlow::Node node) { node instanceof XXE::Sanitizer }
}

from XXEConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "XXE depends on $@.", source.getNode(), "a user-provided value"
