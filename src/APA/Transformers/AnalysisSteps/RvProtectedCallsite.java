package APA.Transformers.AnalysisSteps;

import javafx.util.Pair;
import soot.jimple.Stmt;

import java.util.List;

public class RvProtectedCallsite {
    //pair<Stmt,List<Integer>>
    public Stmt stmt;
    public List<Integer> rv;
    public RvProtectedCallsite(Stmt stmt, List<Integer> rv) {
        this.stmt = stmt;
        this.rv = rv;
    }
}
