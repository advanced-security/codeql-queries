
import python
import semmle.python.Concepts
import semmle.python.ApiGraphs
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources


abstract class LocalSources extends DataFlow::Node { }

class SysArgv extends LocalSources {
  SysArgv() { this = API::moduleImport("sys").getMember("argv").getAUse() }
}
