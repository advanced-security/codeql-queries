import java
import tailor.models.Models
import semmle.code.java.dataflow.FlowSources


// Consider local sources to be under attacker control
class LocalIsRemote extends RemoteFlowSource {
  LocalIsRemote() {
    this instanceof LocalUserInput
  }

  override string getSourceType() { result = "local source type" }
}
