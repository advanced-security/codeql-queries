/**
 * @name Using JS Eval
 * @description Using JS Eval
 * @kind problem
 * @problem.severity warning
 * @security-severity 4.0
 * @id js/using-eval
 * @tags security
 *       external/cwe/cwe-676
 *       static
 */

import javascript
import semmle.javascript.security.dataflow.CodeInjectionCustomizations

from CodeInjection::EvalJavaScriptSink eval
select eval, "Using eval"
