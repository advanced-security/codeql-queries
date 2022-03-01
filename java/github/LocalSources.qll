import java
import semmle.code.java.dataflow.FlowSources

class FileReadAccess extends LocalUserInput {
  FileReadAccess() {
    exists(MethodAccess ma |
      // https://docs.oracle.com/javase/8/docs/api/java/lang/Class.html#getResourceAsStream-java.lang.String-
      ma.getMethod().hasQualifiedName("java.lang", "ClassLoader", "getResourceAsStream") and
      // TODO: static string
      // .getResourceAsStream("config.xml")
      this.asExpr() = ma
    )
  }
}
