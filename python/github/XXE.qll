import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.ApiGraphs

module XXE {
  abstract class Source extends DataFlow::Node { }

  abstract class Sink extends DataFlow::Node { }

  abstract class Sanitizer extends DataFlow::Node { }

  class RemoteFlowSourceAsSource extends Source, RemoteFlowSource { }

  API::Node getPyXMLParser() {
    // Find Insecure parsers
    exists(API::Node nodes, DataFlow::CallCfgNode feature |
      // > from xml.sax import make_parser
      // > parser = make_parser()
      nodes = API::moduleImport("xml.sax").getMember("make_parser") and
      // Make sure that the feature is enabled
      // > from xml.sax.handler import feature_external_ges
      // > parser.setFeature(feature_external_ges, True)
      feature = nodes.getReturn().getMember("setFeature").getACall() and
      feature.getArg(0) =
        API::moduleImport("xml.sax.handler").getMember("feature_external_ges").getAUse() and
      feature.getArg(1).asExpr().(BooleanLiteral).booleanValue() = true and
      result = nodes.getReturn()
    )
  }

  class PyXMLSax extends Sink {
    PyXMLSax() {
      exists(DataFlow::CallCfgNode call |
        // https://github.com/python/cpython/blob/main/Lib/xml/sax/__init__.py#L70
        // > from xml.sax import make_parser
        // > parser = make_parser()
        // > parser.parse("xxe.xml")
        call = getPyXMLParser().getMember("parse").getACall() and
        this = call.getArg(0)
      )
    }
  }

  class PyXMLDom extends Sink {
    PyXMLDom() {
      exists(DataFlow::CallCfgNode call |
        // https://github.com/python/cpython/blob/3.10/Lib/xml/dom/pulldom.py#L331-L349
        // > from xml.dom.pulldom import parseString
        // > parseString(request.body.decode('utf-8'), parser=parser)
        call = API::moduleImport("xml.dom.pulldom").getMember(["parseString", "parse"]).getACall() and
        call.getArgByName("parser") = getPyXMLParser().getAUse() and
        this = call.getArg(0)
      )
    }
  }
}
