/**
 * @name Audit Query
 * @description Audit Query
 * @kind problem
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

from AuditSinks sinks
select sinks, "audit location"
