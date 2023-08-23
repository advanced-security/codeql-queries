/**
 * @name Hard-coded credentials
 * @description Credentials are hard coded in the source code of the application.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 5.9
 * @precision medium
 * @sub-severity medium
 * @id py/hardcoded-credentials
 * @tags security
 *       external/cwe/cwe-259
 *       external/cwe/cwe-321
 *       external/cwe/cwe-798
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.BarrierGuards
import semmle.python.ApiGraphs
import HardcodedFrameworkSecretsInst::PathGraph
import github.HardcodedSecretSinks

class HardcodedValue extends DataFlow::Node {
  HardcodedValue() { exists(StrConst literal | this = DataFlow::exprNode(literal)) }
}

module HardcodedFrameworkSecretsInst = TaintTracking::Global<HardcodedFrameworkSecretsImpl>;

private module HardcodedFrameworkSecretsImpl implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { source instanceof HardcodedValue }

  predicate isSink(DataFlow::Node sink) { sink instanceof CredentialSink }
}

from HardcodedFrameworkSecretsInst::PathNode source, HardcodedFrameworkSecretsInst::PathNode sink
where HardcodedFrameworkSecretsInst::flowPath(source, sink)
select sink.getNode(), source, sink, "Use of $@.", source.getNode(), "hardcoded credentials"
