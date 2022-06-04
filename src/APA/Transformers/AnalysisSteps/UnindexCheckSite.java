package APA.Transformers.AnalysisSteps;

import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;

public class UnindexCheckSite {
    public SootMethod checker;
    public Unit unit;
    public InvokeExpr invoke;
    public UnindexCheckSite(SootMethod checker, Unit unit, InvokeExpr invoke) {
        this.checker = checker;
        this.unit = unit;
        this.invoke = invoke;
    }
}
