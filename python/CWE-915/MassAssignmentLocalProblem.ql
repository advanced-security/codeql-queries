/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision high
 * @sub-severity high
 * @id py/mass-assignment-problem
 * @tags security
 *       external/cwe/cwe-2915
 *       testing
 */

import python
// GitHub Field lib
import github.MassAssignment::MassAssignment

from MassAssignmentConfigInst::PathNode source, MassAssignmentConfigInst::PathNode sink
where MassAssignmentConfigInst::flowPath(source, sink)
select sink, "Use of $@.", source, "mass assignment"
