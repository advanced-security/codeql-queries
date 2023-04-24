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

extensible predicate functionComplexityThreshold(int threshold);

from Callable callable, MetricCallable metrics, int threshold
where callable.getMetrics() = metrics
// TODO: accept limit as a data extension
and metrics.getCyclomaticComplexity() > threshold
and functionComplexityThreshold(threshold)
select callable, "High code complexity for function/method $@: " + metrics.getCyclomaticComplexity() + " > 10",
    callable, callable.toString()
