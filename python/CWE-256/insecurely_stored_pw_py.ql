/**
 * @name Python insecurely stored password
 * @description Password stored insecurely directly in database without hashing with a secure password hash
 * @kind problem
 * @problem.severity error
 * @id python/default-password-db
 * @precision high
 * @tags password
 *       python
 *       external/cwe/cwe-256
 *       external/cwe/cwe-257
 *       external/cwe/cwe-522
 */

private import python
private import semmle.python.dataflow.new.internal.TaintTrackingPublic
private import semmle.python.dataflow.new.internal.DataFlowPublic

class User extends ClassDef {
    Class class_;
    string name;
    Expr base;
    Value ref;
    string password_variable;

    User() {
        this.getDefinedClass() = class_
        and class_.getName() = name
        and class_.getABase() = base
        and base.pointsTo(ref)
        and (
            ref.getName() = "UserMixin"
            and password_variable = "password"
            or
            (
                ref.getName() = "Model"
                and exists(class_.getInitMethod().getArgByName(password_variable))
                and password_variable.regexpMatch("^(?:password|pass|pwd|passwd)$")
            )
        )
    }

    string
    getName() {
        result = name
    }

    Function
    getInit() {
        result = class_.getInitMethod()
    }

    predicate isSecure() {
        exists(ControlFlowNode hash, Call hash_call, AssignStmt assign, Attribute target, Variable self, Name self_access |
            this.getInit().getBody().contains(hash.getNode())
            and hash.inferredValue().getName() = "generate_password_hash"
            and hash_call.contains(hash.getNode())
            and assign.getValue().getAChildNode*() = hash_call
            and assign.getATarget() = target
            and target.getObject("password") = self_access
            and self.getId() = "self"
            and self_access = self.getAnAccess()
        )
    }
}

from User user
where not user.isSecure()
select user, "Insecure 'user' class $@ using 'UserMixin' with no secure password hashing",
    user, user.getName()
