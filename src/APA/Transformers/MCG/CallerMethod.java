package APA.Transformers.MCG;

import soot.SootMethod;
import soot.Unit;

public class CallerMethod {
    Unit callerUnit;
    SootMethod callerMethod;

    public CallerMethod(Unit srcUnit, SootMethod sootMethod) {
        this.callerUnit = srcUnit;
        this.callerMethod = sootMethod;
    }
}
