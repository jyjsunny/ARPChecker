package APA.Transformers.MCG;

import APA.Transformers.Intent.IntentAction;
import APA.Transformers.Intent.IntentCategory;
import APA.Transformers.Intent.IntentData;
import soot.Body;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.AssignStmt;
import soot.jimple.InstanceInvokeExpr;
import soot.jimple.InvokeExpr;
import soot.jimple.InvokeStmt;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class IntentFilter {
    public List<IntentAction> action;
    public List<IntentCategory>  category;
    public List<IntentData> data;
    public Boolean findDef = false;
    public String curParamName;
    public IntentFilter(List<IntentAction> actions, List<IntentCategory> categories, List<IntentData> datas) {
        this.action = actions;
        this.category = categories;
        this.data = datas;
        this.findDef = true;
    }

    public IntentFilter(String curParamName, ArrayDeque<CallerMethod> methodStack) {
        this.curParamName = curParamName;
        this.findDef = false;
    }

    public void backwardSlice(SootMethod sootMethod, Unit unit) {
//        Unit u = unit;
//        Body methodBody;
//        if (sootMethod.hasActiveBody()) {
//            methodBody = sootMethod.getActiveBody();
//        } else {
//            return;
//        }
//        while (true) {
//            try {
//                u = methodBody.getUnits().getPredOf(u);
//            } catch (IllegalStateException e) {
//                break;
//            }
//            /* Invoke Statement */
//            if (u instanceof InvokeStmt) {
//                InvokeExpr expr = ((InvokeStmt) u).getInvokeExpr();
//                String name = "";
//                if(expr instanceof InstanceInvokeExpr)
//                    name = ((InstanceInvokeExpr) expr).getBase().toString();
//                if (!Objects.equals(name, this.curParamName))
//                    continue;
//                //this.resolveInvokeExpr(u, sootMethod);
//            }
//            /* Assign Statement */
//            if (u instanceof AssignStmt) {
//                if (Objects.equals(((AssignStmt) u).getLeftOp().toString(), this.curParamName)) {
//                    if (((AssignStmt) u).containsInvokeExpr()) {
//                        InvokeExpr expr= ((AssignStmt) u).getInvokeExpr();
//                        if (!isSelfDefined(expr.getMethod().getDeclaringClass().getName())) {
//                            this.resolveAssignExpr(u, sootMethod)
//                        } else {
//                            methodStack.push(CallerMethod(u, sootMethod))
//                            this.resolveCalleeReturn(expr.method)
//                            methodStack.poll()
//                        }
//                    } else {
//                        this.curParamName = regexMatchName(u)
//                    }
//                }
//            }
//        }
//        if (!this.findDef) {
//            /* Not find definition of Intent in the method, Intent is passed in, try to trace the caller method */
//            val paramLocals = methodBody.parameterLocals.map { it.name }
//            if (this.curParamName in paramLocals) {
//                resolveCallerPassed(paramLocals.indexOf(this.curParamName))
//            }
//        }
    }

    private void resolveInvokeExpr(Unit u, SootMethod sootMethod) {
    }
}
