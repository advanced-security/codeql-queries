import java
import semmle.code.java.dataflow.FlowSteps


/// Missing taintstep's
// ==============================
// File() `getName` Method contains taints data
class PreserveGetName extends TaintPreservingCallable {
  // new File(TAINT).getName()
  PreserveGetName() { this.getName() = "getName" }

  override predicate returnsTaintFrom(int arg) { arg = -1 }
}
