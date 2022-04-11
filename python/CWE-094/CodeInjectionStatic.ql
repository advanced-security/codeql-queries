/**
 * @name Code injection
 * @description Interpreting unsanitized user input as code allows a malicious user to perform arbitrary
 *              code execution.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 6.0
 * @sub-severity medium
 * @precision very-low
 * @id py/code-injection
 * @tags security
 *       external/cwe/cwe-094
 *       external/cwe/cwe-095
 *       external/cwe/cwe-116
 *       external/owasp/owasp-a1
 *       static
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs

from DataFlow::Node sink
where sink = any(CodeExecution e)
select sink, "Usage of Code Execution function"
