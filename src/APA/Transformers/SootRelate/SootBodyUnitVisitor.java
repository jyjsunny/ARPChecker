package APA.Transformers.SootRelate;

import soot.Unit;
import soot.Value;
import soot.jimple.ArrayRef;
import soot.jimple.InvokeExpr;

public interface SootBodyUnitVisitor {
    public default void visitInvoke(InvokeExpr invoke, Unit unit)
    {

    }
    public default void visitArrayMemberAssign(ArrayRef lv, Value rv, Unit unit)
    {

    }
}
