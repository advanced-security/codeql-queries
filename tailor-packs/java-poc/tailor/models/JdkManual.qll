import java
private import semmle.code.java.dataflow.ExternalFlow

private class JdkManual extends SummaryModelCsv {
  override predicate row(string row) {
    row = [
      "java.lang;String;true;replace;;;Argument[-1];ReturnValue;taint;manual"
    ]
  }
}

