/**
 * @name Function Complexity
 * @description High function complexity
 * @kind problem
 * @problem.severity note
 * @precision low
 * @id java/function-complexity
 * @tags quality
 *       maintainability
 */

import java

from Callable callable, MetricCallable metrics
where callable.getMetrics() = metrics
// TODO: accept limit as a data extension
and metrics.getCyclomaticComplexity() > 10
select callable, "High code complexity for function/method $@: " + metrics.getCyclomaticComplexity() + " > 10",
    callable, callable.toString()
