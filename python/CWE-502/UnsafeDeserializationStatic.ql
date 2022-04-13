/**
 * @name Deserializing untrusted input
 * @description Deserializing user-controlled data may allow attackers to execute arbitrary code.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.5
 * @sub-severity low
 * @precision very-low
 * @id py/unsafe-deserialization-static
 * @tags security
 *       external/cwe/cwe-502
 *       experimental
 *       static
 */

import python
import semmle.python.Concepts
import semmle.python.ApiGraphs

from DataFlow::Node sink, Decoding d
where d.mayExecuteInput() and sink = d
select sink, "Usage of Deserializing function"
