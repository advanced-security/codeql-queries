/**
 * @name Find Imports
 * @description Find Imports
 * @kind problem
 * @problem.severity note
 * @precision high
 * @id js/deprecated-methods
 * @tags security
 *       external/cwe/cwe-477
 */

import javascript
import semmle.javascript.dataflow.DataFlow



from CallExpr call, Expr expr
where
    call.getCalleeName() = "insert" and expr = call.getCallee()
select expr, "Deprecated Methods in MongoDB"
