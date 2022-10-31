/**
 * @name Insecurely stored cryptographic key
 * @kind path-problem
 * @problem.severity error
 * @id javascript/insecurely-stored-key
 */

import javascript
import semmle.javascript.dataflow.TaintTracking
import semmle.javascript.dataflow.DataFlow

import DataFlow::PathGraph

class CommandLineArgument extends DataFlow::Node {
    CommandLineArgument() {
        this = DataFlow::globalVarRef("process").getAPropertyRead("argv").getAPropertyReference()
    }
}

class InsecureKeyConfiguration extends TaintTracking::Configuration {
    InsecureKeyConfiguration() { this = "InsecureKeyConfiguration" }

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
        // an external function that is not a known secure store
        source instanceof ExternalCallWithOutput
        and not isSecureStorage(source)
    }

    override predicate isSink(DataFlow::Node sink) {
        isCreateCiper(sink)
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

// TODO: include SecretManager type, and the package
// import { SecretsManager } from "@aws-sdk/client-secrets-manager";
// let secretsManager = new SecretsManager({...});
// const secret = secretsManager.getSecretValue({...});
predicate isSecureStorage(DataFlow::Node node) {
    exists(MethodCallExpr call |
        call.getCalleeName() = "getSecretValue"
        and call.flow() = node
    )
}

predicate isCreateCiper(DataFlow::Node node) {
    exists(string name|
        name in ["createDecipheriv", "createCipheriv", "createCipher", "createDecipher"] and
        DataFlow::moduleMember("crypto", name).getACall().getArgument(1) = node
    )
}

from InsecureKeyConfiguration insecurecfg, DataFlow::PathNode source, DataFlow::PathNode sink
where insecurecfg.hasFlowPath(source, sink)
select sink, source, sink, "Insecurely stored key used for cryptographic function. Use secure storage for keys."
