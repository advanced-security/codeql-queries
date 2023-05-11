/**
 * @name Audit Flow Query
 * @description Audit Flow Query
 * @kind path-problem
 * @problem.severity error
 * @security-severity 2.0
 * @precision medium
 * @id cs/audit/query
 * @tags security
 *       audit
 */

import csharp
private import semmle.code.csharp.security.dataflow.flowsources.Remote
private import semmle.code.csharp.security.dataflow.flowsources.Local
private import semmle.code.csharp.dataflow.DataFlow::DataFlow::PathGraph
private import github.Audit

class AuditConfiguration extends TaintTracking::Configuration {
  AuditConfiguration() { this = "AuditConfiguration" }

  override predicate isSource(DataFlow::Node source) {
    source instanceof RemoteFlowSource or source instanceof LocalFlowSource
  }

  override predicate isSink(DataFlow::Node sink) { sink instanceof AuditSinks }
}

from AuditConfiguration config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "audit sink"
