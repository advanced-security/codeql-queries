/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 2.0
 * @precision high
 * @sub-severity high
 * @id py/mass-assignment
 * @tags security
 *       external/cwe/cwe-2915
 */

import python
// GitHub Field lib
import github.MassAssignment::MassAssignment

from MassAssignmentLocalConfigInst::PathNode source, MassAssignmentLocalConfigInst::PathNode sink
where MassAssignmentLocalConfigInst::flowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
