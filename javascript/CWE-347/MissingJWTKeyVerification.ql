/**
 * @name JWT missing secret or public key verification
 * @description The application does not verify the JWT payload with a cryptographic secret or public key.
 * @kind problem
 * @problem.severity warning
 * @security-severity 7.0
 * @precision high
 * @id js/jwt-missing-verification
 * @tags security
 *       external/cwe/cwe-347
 */

 import javascript
 import DataFlow
 import semmle.javascript.RestrictedLocations
 
 from DataFlow::CallNode call, Node node, string msg
 where
   (call = DataFlow::moduleMember("jsonwebtoken", "verify").getACall() and
   call.getArgument(1).analyze().getTheBooleanValue() = false
   and node = call.getArgument(1)
   and msg = "This argument disables the integrity enforcement of the token verification.")
   or 
   (call = DataFlow::moduleMember("jose", "decodeJwt").getACall() 
   and node = call
   and msg = "This does not validate the JWS Signature..")
 select node, msg
