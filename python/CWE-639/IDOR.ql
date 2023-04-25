/**
 * @name Python IDOR
 * @description Possible Insecure Direct Object Reference (IDOR) in a Python web application
 * @kind path-problem
 * @problem.severity error
 * @id python/idor
 * @precision low
 * @tags idor
 *       python
 *       audit
 *       external/cwe/cwe-639
 */

private import python
private import semmle.python.dataflow.new.DataFlow
private import DataFlow::PathGraph

import IDOR

from DataFlow::PathNode userdata, DataFlow::PathNode database_arg_path, DatabaseQueryArg database_arg, IdorTaintConfiguration idor_taint, string message
where idor_taint.hasFlowPath(userdata, database_arg_path) and database_arg = database_arg_path.getNode()
and (
    flowToHttpResponse(database_arg) and message = "which is later returned to the user"
    or
    flowToCommit(database_arg, _) and message = "which is later committed to the database"
)
select database_arg_path.getNode(), userdata, database_arg_path, "Unchecked user data $@ flows to database ORM query (with argument $@), " + message,
    userdata, userdata.toString(),
    database_arg, database_arg.toString()
