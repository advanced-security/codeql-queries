/**
 * Contains customizations to the standard library.
 *
 * This module is imported by `java.qll`, so any customizations defined here automatically
 * apply to all queries.
 *
 * Typical examples of customizations include adding new subclasses of abstract classes such as
 * the `RemoteFlowSource` and `AdditionalTaintStep` classes associated with the security queries
 * to model frameworks that are not covered by the standard library.
 */

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
