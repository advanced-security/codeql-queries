private import python
private import semmle.python.dataflow.new.DataFlow
private import semmle.python.dataflow.new.DataFlow2
private import semmle.python.dataflow.new.TaintTracking
private import semmle.python.dataflow.new.TaintTracking2
private import semmle.python.dataflow.new.RemoteFlowSources
private import semmle.python.ApiGraphs
private import semmle.python.Concepts
private import semmle.python.Flow
private import semmle.python.dataflow.new.internal.TaintTrackingPublic

class IdorTaintConfiguration extends TaintTracking::Configuration {
    IdorTaintConfiguration() { this = "IdorTaintConfiguration" }

    override predicate
    isSource(DataFlow::Node source) {
        source instanceof RemoteFlowSource
    }

    override predicate
    isSink(DataFlow::Node sink) {
        sink instanceof DatabaseQueryArg
    }

    override predicate
    isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
        none()
    }

    // some "if" check dominates the dataflow
    override predicate 
    isSanitizer(DataFlow::Node node) {
        node instanceof GuardedByIf
    }

    override
    int
    explorationLimit() {
        result = 10
    }
}

class GuardedByIf extends DataFlow::Node {
    GuardedByIf() {
        ifReachesUse(this)
    }
}

predicate ifDominatesUse(DataFlow::Node node) {
    exists(If ifstmt, Expr test, DataFlow::Node use|
        ifstmt.getTest() = test
        and use.asCfgNode().dominates(node.asCfgNode())
        and useUsePair(node, use)
        and test.contains(use.asExpr())
    )
}

predicate ifReachesUse(DataFlow::Node node) {
    exists(If ifstmt, Expr test, DataFlow::Node use|
        ifstmt.getTest() = test
        and use.asCfgNode().strictlyReaches(node.asCfgNode())
        and useUsePair(node, use)
        and test.contains(use.asExpr())
    )
}

predicate ifDominatesUse(DataFlow::Node node, ControlFlowNode cfgNode) {
    exists(If ifstmt, Expr test, DataFlow::Node use|
        ifstmt.getTest() = test
        and test.contains(use.asExpr())
        and use.asCfgNode().dominates(cfgNode)
        and useUsePair(node, use)
    )
}

predicate ifReachesUse(DataFlow::Node node, ControlFlowNode cfgNode) {
    exists(If ifstmt, Expr test, DataFlow::Node use|
        ifstmt.getTest() = test
        and test.contains(use.asExpr())
        and use.asCfgNode().strictlyReaches(cfgNode)
        and useUsePair(node, use)
    )
}

predicate useUsePair(DataFlow::Node use1, DataFlow::Node use2) {
    use1 != use2 and
    exists(EssaVariable var|
        var.getASourceUse() = use1.asCfgNode() and
        var.getASourceUse() = use2.asCfgNode()
        and not use1.asExpr().isConstant()
        and not use2.asExpr().isConstant()
    )
}

// TODO: useful if we want to know that the IDOR results in user-visible results
predicate inHttpResponse(DataFlow::Node node) {
    exists(Http::Server::HttpResponse response|
        response.getBody().asExpr().getAChildNode*() = node.asExpr()
        and not node.asExpr().isConstant()
    )
}

// BUG: misses real uses
DataFlow::Node dbCommit() {
    exists(API::Node method, CallNode call |
        method = 
        // sqlalchemy -> db.session.commit()
            API::moduleImport("flask_sqlalchemy")
            .getMember("SQLAlchemy")
            .getReturn()
            .getMember("session")
            .getMember("commit")
            and method.getACall().asCfgNode() = call
            and result.asCfgNode() = call
    )
}

class DBCommit extends CallNode {
    CallNode a;
    string name;
    ControlFlowNode object;
    ControlFlowNode parent;

    DBCommit() {
        exists(|
            this.getFunction().(AttrNode).getObject(name) = object
            and name = "commit"
            and object.(AttrNode).getObject("session") = parent
            // TODO: work out how to get higher up than this for SQLAlchemy
        )
    }
}

// post-dominated by db.session.commit() isn't possible
// so we just do 'reaches'
Expr willCommit(DataFlow::Node node) {
    exists(ControlFlowNode commit|
        commit instanceof DBCommit and
        node.asCfgNode().strictlyReaches(commit)
        and result = commit.getNode()
    )
}

class ReturnedToUserConfiguration extends TaintTracking::Configuration {
    ReturnedToUserConfiguration() { this = "ReturnedToUserConfiguration" }

    override predicate
    isSource(DataFlow::Node source) {
        source = source
    }

    override predicate
    isSink(DataFlow::Node sink) {
        inHttpResponse(sink)
    }

    override predicate
    isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
        taintOverMethodWithNoArgs(node1, node2)
    }

    override
    int
    explorationLimit() {
        result = 10
    }
}

// taint across a method call with no arguments
// e.g. object->method()
predicate taintOverMethodWithNoArgs(DataFlow::Node node1, DataFlow::Node node2) {
    exists(CallNode call, ControlFlowNode object |
        call.getFunction().(AttrNode).getObject(_) = object
        and node2.asCfgNode() = call
        and node1.asCfgNode() = object
        and not exists(call.getAnArg())
    )
}

class ReturnedExpr extends DataFlow::Node {
    ReturnedExpr() {
        exists(Return return|
            return.getAChildNode*() = this.asExpr()
        )
    }
}

/*
TODO: Bottle, CherryPy, Dash, Falcon, CubicWeb, Pylons, Pyramid, Web2Py, Storm etc. postgres directly, etc.
https://www.monocubed.com/blog/top-python-frameworks/
https://stackoverflow.com/questions/53428/what-are-some-good-python-orm-solutions
*/

// TODO: this is the "right" way to do it
// BUG: but it doesn't find some uses of query.filter_by() that are in real code
predicate isDBInterface(API::Node method) {
    (
        method = 
        // sqlalchemy -> model.query.filter_by(id=id)
            API::moduleImport("flask_sqlalchemy")
            .getMember("SQLAlchemy")
            .getReturn()
            .getMember("Model")
            .getASubclass()
            .getMember("query")
            .getMember(["filter_by", "filter", "where"])
        or
        // sqlalchemy -> sql statement parameter, e.g. db.engine.execute(...)
        method =
            API::moduleImport("flask_sqlalchemy")
            .getMember("SQLAlchemy")
            .getReturn()
            .getMember("engine")
            .getMember("execute")
        or
        // Django -> ObjectModel.objects.get(id=id)
        method =
            API::moduleImport("django.db")
            .getMember("models")
            .getReturn()
            .getMember("Model")
            .getASubclass()
            .getMember("objects")
            .getMember(["get", "filter"])
        or
        // Peewee ORM -> User.select().where(Person.id == id).get() or User.get(User.id == id)
        method =
            API::moduleImport("peewee")
            .getMember("Model") // ?? is it direct like this? they do 'from peewee import *', so hard to tell, need to test it
            .getASubclass()
            .getMember("select")
            .getReturn()
            .getMember(["get", "where", "get_or_create", "get_by_id"])
    )
}

class DatabaseQueryArg extends DataFlow::Node {

    CallNode a;
    string name;
    ControlFlowNode object;
    ControlFlowNode parent;

    DatabaseQueryArg() {
        // exists(CallNode call, API::Node method|
        //     isDBInterface(method)
        //     and method.getACall().asCfgNode() = call
        //     and this.asCfgNode() = call.getAnArg().getAChild*()
        // )
        a.getFunction().(AttrNode).getObject(name) = object
        and name in ["filter_by", "filter", "where"]
        and a.getAnArg().getAChild*() = this.asCfgNode()
        and object.(AttrNode).getObject("query") = parent
    }

    string getName() {
        result = name
    }

    CallNode getCall() {
        result = a
    }
}

// intra-procedural detection of variable redefinition
// use to prevent control-flow going over a redefinition of a flow-important variable
predicate redefined(Name name_expr, Expr sink, AssignStmt redef) {
    exists(Variable var, string name, ControlFlowNode cfgNode, int startLine|
        redef.defines(var)
        and var.getId() = name
        and name_expr.getId() = name
        and cfgNode = redef.getValue().getAFlowNode()
        and name_expr.getAFlowNode().strictlyReaches(cfgNode)
        and cfgNode.strictlyReaches(sink.getAFlowNode())
        and name = "user"
        and name_expr.getLocation().getStartLine() = startLine
    )
}

/* the controlflow part from database query to commit */
predicate flowToCommit(DatabaseQueryArg database_arg, Expr commit) {
    exists(DataFlow::Node call |
        call.asCfgNode() = database_arg.getCall()
        and commit = willCommit(call)
        and exists(AssignStmt query_assignment, Variable var, Name def |
            query_assignment.defines(var)
            and var.getAnAccess() = def
            and def = query_assignment.getATarget()
            and query_assignment.getValue().contains(call.asExpr())
            and not redefined(def, commit, _)
        )
    )
    and not ifReachesUse(database_arg, commit.getAFlowNode())
}

predicate flowToHttpResponse(DatabaseQueryArg database_arg) {
    exists(DataFlow::Node call, DataFlow::Node return, ReturnedToUserConfiguration cfg2 |
        call.asCfgNode() = database_arg.getCall()
        and cfg2.hasFlow(call, return)
        and not ifReachesUse(database_arg, return.asCfgNode())
    )
}

API::Node testAPI() {
    result = API::moduleImport("flask_sqlalchemy")
    .getMember("SQLAlchemy")
    .getReturn()
    .getMember("Model")
    .getASubclass*()
    .getMember("query")
    //.getMember(["filter_by", "filter", "where"])
}