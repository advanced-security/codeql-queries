/**
 * @name Using JS Eval
 * @description Using JS Eval
 * @kind problem
 * @problem.severity note
 * @id js/using-eval
 * @tags security
 *       external/cwe/cwe-676
 */

import javascript
import semmle.javascript.security.dataflow.CodeInjectionCustomizations

from CodeInjection::EvalJavaScriptSink eval
select eval, "Using eval"
