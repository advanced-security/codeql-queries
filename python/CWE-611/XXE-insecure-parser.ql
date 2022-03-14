/**
 * @name XXE using Insecure XML Parser
 * @description XML Parser using insecure feature
 * @kind problem
 * @problem.severity error
 * @security-severity 8.0
 * @sub-severity high
 * @precision medium
 * @id py/xxe
 * @tags security
 *       external/cwe/cwe-611
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.dataflow.new.TaintTracking
import semmle.python.Concepts
import semmle.python.ApiGraphs
import github.XXE

from API::Node parsers
where parsers = XXE::getPyXMLParser()
select parsers, "XML Parser using insecure feature"
