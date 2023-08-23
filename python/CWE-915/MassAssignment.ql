/**
 * @name Mass assignment
 * @description Mass assignment is a vulnerability that allows an attacker to
 *             modify multiple attributes of a model at once.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @sub-severity high
 * @id py/mass-assignment
 * @tags security
 *       external/cwe/cwe-2915
 */

import python
// import MassAssignmentConfigInst::PathGraph
// GitHub Field lib
import github.MassAssignment::MassAssignment

from MassAssignmentConfigInst::PathNode source, MassAssignmentConfigInst::PathNode sink
where MassAssignmentConfigInst::flowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "mass assignment"
