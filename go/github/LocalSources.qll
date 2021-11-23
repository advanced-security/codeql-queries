import go

// ========== Sources ==========
module LocalSources {
  abstract class Sources extends DataFlow::Node { }

  // https://pkg.go.dev/os#Getenv
  class OsGetenv extends Sources, DataFlow::CallNode {
    OsGetenv() { this.getTarget().hasQualifiedName(package("os", ""), "Getenv") }
  }

  // https://pkg.go.dev/flag
  class Flag extends Sources, DataFlow::CallNode {
    Flag() { this.getTarget().hasQualifiedName(package("flag", ""), "String") }
  }
}
