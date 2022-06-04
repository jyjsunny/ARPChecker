package APA.Transformers.AnalysisSteps;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;

public class UnindexRequestSite {
    public SootMethod requester;
    public Unit unit;
    public InvokeExpr invoke;
    public UnindexRequestSite(SootMethod checker, Unit unit, InvokeExpr invoke) {
        this.requester = checker;
        this.unit = unit;
        this.invoke = invoke;
    }
}
