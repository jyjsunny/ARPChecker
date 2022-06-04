package APA.Transformers.Type1Transformers;

import APA.Transformers.CFG;
import APA.Transformers.Config;
import APA.Transformers.ManualOp.DoClasses;
import soot.*;
import soot.jimple.IfStmt;
import soot.jimple.Stmt;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;
import soot.toolkits.scalar.SimpleLocalDefs;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class BillTransformer extends BodyTransformer{
    private static final HashMap<SootMethod, LocalDefs> defs = new HashMap<>();//defs用于存储当前sootmethod对应的LocalDefs值

    public static List<Unit> handleRdFactAt(SootMethod method, Local local, Stmt stmt) {
//        try{
//            Objects.equals(method.getSignature(), Config.HANDLE_API)
//        }
            return defs.get(method).getDefsOfAt(local, stmt);//得到local变量在到达method中的stmt之前被定义过的units

    }

    @Override
    protected void internalTransform(Body body, String phase, Map<String, String> options) {
        SootMethod method = body.getMethod();
        if(DoClasses.isHandleApi(method)) {//onRequestPermissionsResult
            UnitGraph graph = CFG.getUnitGraph(method);//找到需要查找当前method对应permission值的method对应的UnitGraph：graph
            assert graph != null;
            defs.put(method, new SimpleLocalDefs(graph));//method-method的unitgraph中包含的局部变量定义
        }
    }
}
