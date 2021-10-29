import python
import semmle.python.ApiGraphs

abstract class LoggingSinks extends DataFlow::Node { }

class PrintMethod extends LoggingSinks {
  PrintMethod() {
    exists(DataFlow::Node call |
      call = API::builtin("print").getACall() and
      this = call
    )
  }
}

class LoggingFramework extends LoggingSinks {
  LoggingFramework() {
    exists(DataFlow::Node call, API::Node node |
      (
        node = API::moduleImport("logging") and
        (
          call = node.getMember("info").getACall()
          or
          call = node.getMember("debug").getACall()
          or
          call = node.getMember("warning").getACall()
          or
          call = node.getMember("error").getACall()
        )
      ) and
      this = call
    )
  }
}
