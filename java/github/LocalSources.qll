import java
import semmle.code.java.dataflow.FlowSources

class FileReadAccess extends LocalUserInput {
  FileReadAccess() {
    exists(MethodAccess ma |
      // https://docs.oracle.com/javase/8/docs/api/java/lang/Class.html#getResourceAsStream-java.lang.String-
      (
        ma.getMethod().hasQualifiedName("java.lang", "Class", "getResourceAsStream") or
        ma.getMethod().hasQualifiedName("java.lang", "ClassLoader", "getResourceAsStream") or
        // Finds any method that has the name "getResourceAsStream"
        ma.getMethod().hasQualifiedName(_, _, "getResourceAsStream")
      ) and
      this.asExpr() = ma.getArgument(0)
    )
  }
}

class FileWriteAccess extends LocalUserInput {
  FileWriteAccess() {
    exists(MethodAccess ma |
      // https://docs.oracle.com/javase/7/docs/api/java/nio/file/Files.html#copy(java.io.InputStream,%20java.nio.file.Path,%20java.nio.file.CopyOption...)
      ma.getMethod().hasQualifiedName("java.nio.file", "Files", "copy") and
      ma.getArgument(0) = this.asExpr()
      or
      // https://docs.oracle.com/javase/7/docs/api/java/io/OutputStream.html
      ma.getMethod().hasQualifiedName("java.io", "OutputStream", "write") and
      ma.getArgument(0) = this.asExpr()
    )
  }
}
