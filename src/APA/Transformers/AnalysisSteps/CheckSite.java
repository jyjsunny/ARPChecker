package APA.Transformers.AnalysisSteps;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;

public class CheckSite {
    public int i;
    public SootMethod checker;
    public Unit unit;
    public InvokeExpr invoke;
    public CheckSite(int i, SootMethod checker, Unit unit, InvokeExpr invoke) {
        this.i=i;
        this.checker = checker;
        this.unit = unit;
        this.invoke = invoke;
    }
}
