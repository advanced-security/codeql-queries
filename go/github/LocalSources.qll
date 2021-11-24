import go

// ========== Sources ==========
module LocalSources {
  abstract class Sources extends DataFlow::Node { }

  // https://pkg.go.dev/os#pkg-variables
  // class OsArgs extends Sources {
  //   OsArgs() {
  //     exists(ValueEntity value | value.hasQualifiedName(package("os", ""), "Args") and this = value)
  //   }
  // }
  class OsGetenv extends Sources, DataFlow::CallNode {
    OsGetenv() {
      // https://pkg.go.dev/os#Getenv
      this.getTarget().hasQualifiedName(package("os", ""), "Getenv")
      or
      // https://pkg.go.dev/os#Environ
      this.getTarget().hasQualifiedName(package("os", ""), "Environ")
    }
  }

  // https://pkg.go.dev/flag
  class Flag extends Sources, DataFlow::CallNode {
    Flag() { this.getTarget().hasQualifiedName(package("flag", ""), "String") }
  }
}
