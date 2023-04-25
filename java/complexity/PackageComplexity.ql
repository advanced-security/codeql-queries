/**
 * @name Package Complexity
 * @description High package complexity
 * @kind problem
 * @problem.severity note
 * @precision low
 * @id java/package-complexity
 * @tags quality
 *       maintainability
 */

import java

external predicate packageComplexityThreshold(int threshold);

from Package package, MetricPackage metrics, int threshold
where package.getMetrics() = metrics
// TODO: accept limit as a data extension
and metrics.getCyclomaticComplexity() > threshold
and packageComplexityThreshold(threshold)
select package, "High code complexity for package $@: " + metrics.getCyclomaticComplexity() + " > " + threshold,
    package, package.toString()
