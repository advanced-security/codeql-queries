/**
 * @name Possible Reflected Cross-Site Scripting
 * @description Insecure dangerouslySetInnerHTML() function can lead to reflected XSS.
 * @kind problem
 * @problem.severity error
 * @security-severity 3.0
 * @precision high
 * @id js/reflected-xss
 * @tags security
 *       heuristic
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
private import semmle.javascript.security.dataflow.DomBasedXssCustomizations
import DataFlow::PathGraph

from DomBasedXss::DangerouslySetInnerHtmlSink sink
select sink.asExpr(), "React's dangerouslySetInnerHTML is being used."
