import java
private import semmle.code.java.dataflow.ExternalFlow

private class JdkManual extends SummaryModelCsv {
  override predicate row(string row) {
    row = [
      "java.lang;String;true;replace;;;Argument[-1];ReturnValue;taint;manual",
      // Exception's / Throwable's
      "java.lang;Throwable;true;toString;;;Argument[-1];ReturnValue;taint;manual",
      "java.lang;Throwable;true;getMessage;;;Argument[-1];ReturnValue;taint;manual"
    ]
  }
}

