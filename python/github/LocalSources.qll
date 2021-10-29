private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.Concepts
private import semmle.python.dataflow.new.BarrierGuards
private import semmle.python.ApiGraphs
private import DataFlow::PathGraph

// ========== Sources ==========
abstract class LocalSources extends DataFlow::Node { }

// Standard Input from user
class STDInputSources extends LocalSources {
  STDInputSources() {
    exists(DataFlow::Node call |
      (
        // v = input("Input?")
        call = API::builtin("input").getACall()
        or
        // https://docs.python.org/3/library/fileinput.html
        call = API::moduleImport("fileinput").getMember("input").getACall()
      ) and
      this = call
    )
  }
}

// Command Line Arguments
class CommandLineArgumentsSources extends LocalSources {
  CommandLineArgumentsSources() {
    exists(DataFlow::Node call |
      (
        // v = sys.args[1]
        call = API::moduleImport("sys").getMember("argv").getAUse()
        or
        // parser = argparse.ArgumentParser(__name__)
        // ...
        // arguments = parser.parse_args()
        // v = arguments.t     # user input
        // TODO: This doesn't work but needs supported
        call = API::moduleImport("argparse").getMember("ArgumentParser").getAUse()
      ) and
      this = call
    )
  }
}

// Local Enviroment Variables
class EnviromentVariablesSources extends LocalSources {
  EnviromentVariablesSources() {
    exists(DataFlow::Node call |
      (
        // os.getenv('abc')
        call = API::moduleImport("os").getMember("getenv").getACall()
        or
        // os.environ['abc']
        // os.environ.get('abc')
        call = API::moduleImport("os").getMember("environ").getAUse()
      ) and
      this = call
    )
  }
}

// Local File Reads
class FileReadSource extends LocalSources {
  FileReadSource() {
    exists(DataFlow::Node call |
      (
        // https://docs.python.org/3/library/functions.html#open
        // var = open('abc.txt')
        call = API::builtin("open").getACall()
        or
        // https://docs.python.org/3/library/os.html#os.open
        call = API::moduleImport("os").getMember("open").getACall()
      ) and
      this = call
    )
  }
}
