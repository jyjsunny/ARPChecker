package APA.Transformers;

import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.toolkits.graph.Block;

public class Tri {
    public Block block;
    public Unit unit;
    public InvokeExpr invoke;
    public Tri(Block block, Unit unit, InvokeExpr invoke) {
        this.block = block;
        this.unit = unit;
        this.invoke = invoke;
    }
}
