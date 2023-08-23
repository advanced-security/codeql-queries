/**
 * @name Audit: Cross-site scripting using Flask Jinja2 templates
 * @description Templates are vulnerable to cross-site scripting if they are
 *              rendered with untrusted data.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision very-low
 * @id py/audit/xss-jinja2
 * @tags security
 *       external/cwe/cwe-079
 *       audit
 */

import python
import ConfigurationInst::PathGraph
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.security.dataflow.ReflectedXSSCustomizations

class DynamicTemplate extends DataFlow::Node {
  DynamicTemplate() {
    this =
      API::moduleImport("flask")
          .getMember("render_template")
          .getACall()
          .getKeywordParameter(_)
          .asSink()
  }
}

module ConfigurationInst = TaintTracking::Global<ConfigurationImpl>;

private module ConfigurationImpl implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof ReflectedXss::Source }

  predicate isSink(DataFlow::Node sink) { sink instanceof DynamicTemplate }

  predicate isBarrier(DataFlow::Node node) { node instanceof ReflectedXss::Sanitizer }
}

from ConfigurationInst::PathNode source, ConfigurationInst::PathNode sink
where ConfigurationInst::flowPath(source, sink)
select sink.getNode(), source, sink, "Cross-site scripting vulnerability due to a $@.",
  source.getNode(), "user-provided value"
