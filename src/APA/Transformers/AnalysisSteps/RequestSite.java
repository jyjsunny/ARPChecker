package APA.Transformers.AnalysisSteps;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;

public class RequestSite {
    public int i;
    public SootMethod requester;
    public Unit unit;
    public InvokeExpr invoke;
    public RequestSite(int i, SootMethod checker, Unit unit, InvokeExpr invoke) {
        this.i=i;
        this.requester = checker;
        this.unit = unit;
        this.invoke = invoke;
    }
}
