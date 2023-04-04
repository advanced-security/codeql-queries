/**
 * @name Command Injection into Runtime.exec() with dangerous command
 * @description High sensitvity and precision version of java/command-line-injection, designed to find more cases of command injection in rare cases that the default query does not find
 * @kind path-problem
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @id java/command-line-injection-extra
 * @tags security
 *       external/cwe/cwe-078
 */

import java
import semmle.code.java.frameworks.javaee.ejb.EJBRestrictions
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.FlowSources

import DataFlow::PathGraph


// a static string of an unsafe executable tainting arg 0 of Runtime.exec()
class ExecTaintConfiguration extends TaintTracking::Configuration {
    ExecTaintConfiguration() { this = "ExecTaintConfiguration" }

    override
    predicate
    isSource(DataFlow::Node source) {
        source.asExpr() instanceof StringLiteral
        and source.asExpr().(StringLiteral).getValue() instanceof UnSafeExecutable
    }

    override
    predicate
    isSink(DataFlow::Node sink) {
        exists(RuntimeExecMethod method, MethodAccess call |
            call.getMethod() = method
            and sink.asExpr() = call.getArgument(0)
        )
    }

    override
    predicate
    isSanitizer(DataFlow::Node node) {
        node.asExpr().getFile().isSourceFile() and
        (
            node instanceof AssignToNonZeroIndex
            or node instanceof ArrayInitAtNonZeroIndex
            or node instanceof StreamConcatAtNonZeroIndex
            or node.getType() instanceof PrimitiveType
            or node.getType() instanceof BoxedType
        )
    }
}


// taint flow from user data to args of the command
class ExecTaintConfiguration2 extends TaintTracking::Configuration {
    ExecTaintConfiguration2() { this = "ExecTaintConfiguration2" }

    override
    predicate
    isSource(DataFlow::Node source) {
        source instanceof RemoteFlowSource
        or source instanceof LocalUserInput
    }

    override
    predicate
    isSink(DataFlow::Node sink) {
        exists(RuntimeExecMethod method, MethodAccess call, int index |
            call.getMethod() = method
            and sink.asExpr() = call.getArgument(index)
        )
    }

    override
    predicate
    isSanitizer(DataFlow::Node node) {
        node.asExpr().getFile().isSourceFile() and
        (
            node.getType() instanceof PrimitiveType
            or node.getType() instanceof BoxedType
        )
    }
}


// array[3] = node
class AssignToNonZeroIndex extends DataFlow::Node {
    AssignExpr assign;
    ArrayAccess access;

    AssignToNonZeroIndex() {
        assign.getDest() = access
        and access.getIndexExpr().(IntegerLiteral).getValue() != "0"
        and assign.getSource() = this.asExpr()
    }
}


// String[] array = {"a", "b, "c"};
class ArrayInitAtNonZeroIndex extends DataFlow::Node {
    ArrayInit init;
    int index;

    ArrayInitAtNonZeroIndex() {
        init.getInit(index) = this.asExpr()
        and index != 0
    }
}

// Stream.concat(Arrays.stream(array_1), Arrays.stream(array_2))
class StreamConcatAtNonZeroIndex extends DataFlow::Node {
    MethodAccess call;
    int index;

    StreamConcatAtNonZeroIndex() {
        call.getMethod().getQualifiedName() = "java.util.stream.Stream.concat"
        and call.getArgument(index) = this.asExpr()
        and index != 0
    }
}


// allow list of executables that execute their arguments
// TODO: extend with data extensions
class UnSafeExecutable extends string {
    bindingset[this]
    UnSafeExecutable() {
        this.regexpMatch("^(|.*/)([a-z]*sh|javac?|python[23]?|perl|[Pp]ower[Ss]hell|php|node|deno|bun|ruby|osascript|cmd|Rscript|groovy)(\\.exe)?$")
    }
}


from DataFlow::PathNode source, DataFlow::PathNode sink,  ExecTaintConfiguration2 conf, MethodAccess call, int index, DataFlow::Node sourceCmd, DataFlow::Node sinkCmd, ExecTaintConfiguration confCmd
where call.getMethod() instanceof RuntimeExecMethod
and sink.getNode().asExpr() = call.getArgument(index)
// this is a command-accepting method, but the first argument is not directly tainted
and (
    confCmd.hasFlow(sourceCmd, sinkCmd)
    and sinkCmd.asExpr() = call.getArgument(0)
    and sourceCmd != source.getNode()
)
and conf.hasFlow(source.getNode(), sink.getNode())
select sink, source, sink, "Call to dangerous java.lang.Runtime.exec() with command '$@' with arg from untrusted input '$@'",
    sourceCmd, sourceCmd.toString(),
    source.getNode(), source.toString()
