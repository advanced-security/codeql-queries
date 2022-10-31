/**
 * @name Insecure or static IV used in cryptographic function
 * @kind path-problem
 * @problem.severity error
 * @id javascript/insecure-iv
 */

import javascript
import semmle.javascript.dataflow.TaintTracking

import DataFlow::PathGraph

class StaticIVConfiguration extends TaintTracking::Configuration {
    StaticIVConfiguration() { this = "StaticIVConfiguration" }

    override predicate isSource(DataFlow::Node source) {
        exists(Literal literal|literal.flow() = source)
    }

    override predicate isSink(DataFlow::Node sink) {
        isCreateIV(sink)
    }
}

class RandomIVConfiguration extends TaintTracking::Configuration {
    RandomIVConfiguration() { this = "RandomIVConfiguration" }

    override predicate isSource(DataFlow::Node source) {
        isSecureRandom(source)
    }

    override predicate isSink(DataFlow::Node sink) {
        isCreateIV(sink)
    }
}

class CommandLineArgument extends DataFlow::Node {
    CommandLineArgument() {
        this = DataFlow::globalVarRef("process").getAPropertyRead("argv").getAPropertyReference()
    }
}

class InsecureIVConfiguration extends TaintTracking::Configuration {
    InsecureIVConfiguration() { this = "RandomIVConfiguration" }

    override predicate isSource(DataFlow::Node source) {
        exists(Literal literal|literal.flow() = source)
        or
        source instanceof DataFlow::ArrayLiteralNode
        or
        source instanceof RemoteFlowSource
        or
        source instanceof FileSystemReadAccess
        or
        source instanceof DatabaseAccess
        or
        source instanceof CommandLineArgument
        or
        // an external function that is not a known source of randomness
        source instanceof ExternalCallWithOutput
        and not isSecureRandom(source)
    }

    override predicate isSink(DataFlow::Node sink) {
        isCreateIV(sink)
    }
}

class ExternalCallWithOutput extends DataFlow::Node {
    CallExpr call;

    ExternalCallWithOutput() {
        not exists(MethodCallExpr method_call, ThisExpr this_expr| method_call = call and method_call.getReceiver() = this_expr )
        and
        (
            (this = call.flow() and not exists(call.getAnArgument().flow().getAPredecessor()))
            or
            (this = call.getAnArgument().flow() and not this.asExpr() instanceof Literal
            and not exists(call.getAnArgument().flow().getAPredecessor()))
        )
    }
}

predicate isSecureRandom(DataFlow::Node node) {
    exists(string name|
        name in ["randomBytes", "getRandomValues"] and
        DataFlow::moduleMember("crypto", name).getACall() = node
    )
    or
    exists(string name|
        name in ["randomFill", "randomFillSync"] and
        DataFlow::moduleMember("crypto", name).getACall().getArgument(0) = node
    )
    or
    exists(string name|
        name in ["randomKey", "randomString"] and
        DataFlow::moduleMember("crypto-extra", name).getACall() = node
    )
    or
    exists(string name|
        name in ["cryptoRandomString", "cryptoRandomStringAsync"] and
        DataFlow::moduleMember("crypto-random-string", name).getACall() = node
    )
    or
    exists(string name|
        name in ["secureRandom", "randomArray", "randomUint8Array", "randomBuffer"] and
        DataFlow::moduleMember("secure-random", name).getACall() = node
    )
}

predicate isCreateIV(DataFlow::Node node) {
    exists(string name|
        name in ["createDecipheriv", "createCipheriv"] and
        DataFlow::moduleMember("crypto", name).getACall().getArgument(2) = node
    )
}

from InsecureIVConfiguration insecurecfg, DataFlow::PathNode source, DataFlow::PathNode sink
where insecurecfg.hasFlowPath(source, sink)
select sink, source, sink, "Insecure IV used for cryptographic function. Use a secure random source for IVs."
