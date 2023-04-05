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

from Package package, MetricPackage metrics
where package.getMetrics() = metrics
// TODO: accept limit as a data extension
and metrics.getCyclomaticComplexity() > 100
select package, "High code complexity for package $@: " + metrics.getCyclomaticComplexity() + " > 100",
    package, package.toString()
