import go
import semmle.go.dataflow.DataFlow
import semmle.go.dataflow.TaintTracking
import semmle.go.Scopes

// ========== Sources ==========

abstract class Sources extends DataFlow::Node { }

// ----------------------------------------------------
// Used for finding Selections or Calls for Go imports 
// ----------------------------------------------------

//class UseOfGoImports extends Sources { 
  //UseOfGoImports () {
    //exists ( ValueEntity read, 
             //DataFlow::Package pkg | 
             //read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
             //and ( this.toString().regexpMatch("selection of.*")
              //or this.toString().regexpMatch("call to .*") )
    //)
  //}
//}

// ----------------------------------------------------

class OsCmd extends Sources {
  OsCmd() {
    exists ( ValueEntity read, 
      DataFlow::Package pkg | 
      read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
      and this.toString() = "selection of Run"
    ) 
  }
}

class OsExec extends Sources {
  OsExec() {
    exists ( ValueEntity read, 
             DataFlow::Package pkg | 
             read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
             and this.toString() = "selection of Command"
    )
  }
}

class OsArgs extends Sources { 
  OsArgs() {
    exists ( ValueEntity read, 
             DataFlow::Package pkg | 
             read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
             and this.toString() = "selection of Args"
    )
  }
}

// Not currently working (need a test case)
//class OsGetenv extends Sources, DataFlow::CallNode {
  //OsGetenv() {
    //// https://pkg.go.dev/os#Getenv
    //this.getTarget().hasQualifiedName(package("os", ""), "Getenv")
    //or
    //// https://pkg.go.dev/os#Environ
    //this.getTarget().hasQualifiedName(package("os", ""), "Environ")
  //}
//}

  // https://pkg.go.dev/flag
class Flag extends Sources {
    Flag() {
      exists ( ValueEntity read, 
               DataFlow::Package pkg | 
               read.getScope().getEntity(_) = pkg.getScope().getEntity(_)
               and 
               ( this.toString() = "selection of String"
               or this.toString() = "selection of Parse" )
      )
    }
}