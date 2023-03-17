import python
import semmle.python.dataflow.new.DataFlow

predicate findByLocation(DataFlow::PartialPathNode node, string relative_path, int linenumber) {
  node.getNode().getLocation().getFile().getRelativePath() = relative_path and
  node.getNode().getLocation().getStartLine() = linenumber
}
