/**
 * @name Possible Reflected Cross-Site Scripting
 * @description Insecure dangerouslySetInnerHTML() function can lead to reflected XSS.
 * @kind problem
 * @problem.severity error
 * @security-severity 3.0
 * @id js/reflected-xss
 * @tags security
 *       heuristic
 *       external/cwe/cwe-079
 *       external/cwe/cwe-116
 */

import javascript
private import semmle.javascript.security.dataflow.DomBasedXssCustomizations

from DataFlow::Node sink
where sink instanceof DomBasedXss::DangerouslySetInnerHtmlSink
select sink, "React's dangerouslySetInnerHTML is being used."
