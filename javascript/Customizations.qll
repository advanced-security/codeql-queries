/**
 * Contains customizations to the standard library.
 *
 * This module is imported by `javascript.qll`, so any customizations defined here automatically
 * apply to all queries.
 *
 * Typical examples of customizations include adding new subclasses of abstract classes such as
 * `FileSystemAccess`, or the `Source` and `Sink` classes associated with the security queries
 * to model frameworks that are not covered by the standard library.
 */

import javascript

module WebgoatDomXss{
  private import semmle.javascript.security.dataflow.XssThroughDomQuery


  class WgAjax extends Source {
    WgAjax() { this = any(WebGoatAjaxCall jqac).getAResponseDataNode(_, _) }
  }
  

class WebGoatAjaxCall extends ClientRequest::Range {
    WebGoatAjaxCall() { 
      this = jquery().getAMemberCall("ajax") or 
      this = jquery().getAMemberCall("get") or
      this = jquery().getAMemberCall("post") or
      this = jquery().getAMemberCall("put") or
      this = jquery().getAMemberCall("delete") or
      this = jquery().getAMemberCall("head") or
      this = jquery().getAMemberCall("options") or
      this = jquery().getAMemberCall("patch") or 
      this = jquery().getAMemberCall("getJSON") or
      this = jquery().getAMemberCall("getScript") or
      this = jquery().getAMemberCall("getJSONP") 
    }
  
    override DataFlow::Node getUrl() {
      result = this.getArgument(0) and not exists(this.getOptionArgument(0, _))
      or
      result = this.getOptionArgument([0 .. 1], "url")
    }
  
    override DataFlow::Node getHost() { none() }
  
    override DataFlow::Node getADataNode() { result = this.getOptionArgument([0 .. 1], ["data"]) }
  
    private string getResponseType() {
      this.getOptionArgument([0 .. 1], "dataType").mayHaveStringValue(result)
    }
  
    override DataFlow::Node getAResponseDataNode(string responseType, boolean promise) {
      (
        responseType = this.getResponseType()
        or
        not exists(this.getResponseType()) and responseType = ""
      ) and
      promise = false and
      (
        result =
          this.getOptionArgument([0 .. 1], "success")
              .getALocalSource()
              .(DataFlow::FunctionNode)
              .getParameter(0)
        or
        result =
          getAResponseNodeFromAnXHRObject(this.getOptionArgument([0 .. 1],
              any(string method | method = "error" or method = "complete"))
                .getALocalSource()
                .(DataFlow::FunctionNode)
                .getParameter(0))
        or
        result = getAnAjaxCallbackDataNode(this)
      )
    }
  
    private DataFlow::SourceNode getAResponseNodeFromAnXHRObject(DataFlow::SourceNode obj) {
        result = obj.getAPropertyRead(any(string s | s = ["responseText", "responseXML", "responseJSON"]))
      }
      
      private DataFlow::Node getAnAjaxCallbackDataNode(ClientRequest::Range request) {
        result =
          request.getAMemberCall(any(string s | s = "done" or s = "then")).getCallback(0).getParameter(0)
        or
        result =
          getAResponseNodeFromAnXHRObject(request.getAMemberCall("fail").getCallback(0).getParameter(0))
      }    
  }
}
