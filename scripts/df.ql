/**
 * @name Uncontrolled data used in network request
 * @description Sending network requests with user-controlled data allows for request forgery attacks.
 * @id go/ssrf
 * @kind path-problem
 * @problem.severity error
 * @precision high
 * @tags security
 *       experimental
 *       external/cwe/cwe-918
 */

import go

predicate isTargetParam(Parameter p) {
  exists(Function f | f.getName() = "array_oob_from_buffer4" and p = f.getAParameter())
}

predicate ch2(DataFlow::Node n, DataFlow::Node n2) {
  exists(Assignment ass, StarExpr se |
    ass.getRhs().getAChild*() = se and se = n2.asExpr() and se.getBase() = n.asExpr()
  )
  or
  exists(StarExpr se | se = n2.asExpr() and se.getBase() = n.asExpr())
  or
  exists(AddExpr ae | ae.getAnOperand().getAChild*() = n.asExpr() and ae = n2.asExpr())
  or
  exists(IndexExpr ie | ie.getBase() = n.asExpr() and ie = n2.asExpr())
  or
  exists(DataFlow::CallNode cn | cn.getTarget().getName() = "ida2codeql_assign_helper" |
    n = cn.getArgument(1) and
    n2.(DataFlow::PostUpdateNode).getPreUpdateNode() = cn.getArgument(0)
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Function f |
      f.getName() = "array_oob_from_buffer4" and
      source.asParameter() = f.getAParameter()
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) { ch2(node1, node2) }

  predicate isSink(DataFlow::Node sink) {
    exists(CallExpr ce |
      // ce.getTarget().getName() = "t2_sink2" and
      sink.asExpr() = ce.getAnArgument()
    )
  }
}

module Flow = DataFlow::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, CallExpr ce
where Flow::flowPath(source, sink) and ce.getAnArgument() = sink.getNode().asExpr()
select source, source, sink, ce.toString()
