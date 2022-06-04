package APA.Transformers.Type1Transformers;


import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.apiMethod;
import heros.InterproceduralCFG;
import javafx.util.Pair;
import jdk.nashorn.internal.runtime.regexp.joni.constants.StringType;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.jimple.toolkits.ide.JimpleIFDSSolver;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class SunnyTransformer extends SceneTransformer {
    private static final Map<SootField, Set<DefinitionStmt>> fieldFact = new ConcurrentHashMap<>();
    public static StringFactSolver SunnySolver;
    public static JimpleBasedInterproceduralCFG icfg = new JimpleBasedInterproceduralCFG();
    public static Map<SootMethod, StringFactSolver> otfSolvers  = new HashMap<>();

    //这里的unit是包含CHECK_API调用的
    public static Set<Permission> concretePermissionValuesAt(Unit unit) {
        Map<Value, Set<Value>> results = stringConcreteFactAt(unit);
        Stmt stmt = (Stmt) unit;
        List<Value> args = stmt.getInvokeExpr().getArgs();
        //实现：strArg=args.firstOrNull{it.isStringType()}
        Value strArg = null;
        for(Value arg : args)
        {
            if(arg.getType().toString().startsWith("java.lang.String"))
            {
                strArg = arg;
                break;
            }
        }
        Set<String> concretePermissions = new ConcurrentHashSet<>();
        if(strArg instanceof StringConstant)
            concretePermissions.add(((StringConstant) strArg).value);
        else
        {
            Set<Value> strc = new ConcurrentHashSet<>();
            for(Value v:results.get(strArg))
            {
                if(v instanceof StringConstant)
                {
                    if(Permission.isPermissionString(((StringConstant)v).value))
                        concretePermissions.add(((StringConstant)v).value);
                }
            }
        }
        Set<Permission> resConcretePermissions = new ConcurrentHashSet<>();
        if(!concretePermissions.isEmpty())
        {
            //PrecomputeAnalyzer.add(stmt, true)
            for(String s:concretePermissions)
            {
                Permission p = new Permission(s);
                resConcretePermissions.add(p);
            }
        }
        return resConcretePermissions;
    }

    private static Map<Value, Set<Value>> stringConcreteFactAt(Unit stmt) {
        Map<Value, Set<DefinitionStmt>> results1 = strDataflowFactAt(stmt, SunnySolver);
        Map<Value, Set<DefinitionStmt>> results2 = strConstantFactAt(stmt);
        Map<Value, Set<Value>> refinedResults = new HashMap<>();
        //分别遍历results1和results2
        for(Map.Entry<Value, Set<DefinitionStmt>> p : results1.entrySet())
        {
            if(!refinedResults.containsKey(p.getKey()))
                refinedResults.put(p.getKey(),new HashSet<>());
            Set<Value> res = new ConcurrentHashSet<>();
            for(DefinitionStmt d:p.getValue())
            {
                res.add(d.getRightOp());
            }
            refinedResults.put(p.getKey(),res);
        }
        for(Map.Entry<Value, Set<DefinitionStmt>> p : results2.entrySet())
        {
            if(!refinedResults.containsKey(p.getKey()))
                refinedResults.put(p.getKey(),new HashSet<>());
            Set<Value> res = new ConcurrentHashSet<>();
            for(DefinitionStmt d:p.getValue())
            {
                res.add(d.getRightOp());
            }
            refinedResults.put(p.getKey(),res);
        }
        return refinedResults;

    }

    private static Map<Value, Set<DefinitionStmt>> strConstantFactAt(Unit unit) {
        Stmt stmt = (Stmt)unit;
        Map<Value, Set<DefinitionStmt>> refinedResults = new HashMap<>();
        // 添加字符串文字参数
        if(stmt.containsInvokeExpr())
        {
            int idx = 0;
            for(Value arg: stmt.getInvokeExpr().getArgs())
            {
                if(arg instanceof StringConstant)
                {
                    Local argValue = Jimple.v().newLocal("$$p"+idx, arg.getType());
                    AssignStmt defStmt = Jimple.v().newAssignStmt(argValue, arg);
                    refinedResults.put(argValue,Collections.singleton(defStmt));
                }
                idx++;
            }
        }
        return refinedResults;
    }

    private static Map<Value, Set<DefinitionStmt>> strDataflowFactAt(Unit unit, StringFactSolver solver) {
        Stmt stmt = (Stmt)unit;
        Map<Value, Set<DefinitionStmt>> refinedResults = new HashMap<>();
        // 通过ifds计算到达stmt的到达定义数据流事实。
        for(Pair<Value, Set<DefinitionStmt>> p : solver.solver.ifdsResultsAt(stmt))
        {
            Set<DefinitionStmt> pDefs = new ConcurrentHashSet<>();
            if(!refinedResults.containsKey(p.getKey()))
                refinedResults.put(p.getKey(),new HashSet<>());
            for(DefinitionStmt def : p.getValue())
            {
                //把对应unit位置，修改过的definitionstmt加入到refinedResults[unit]
                Value rval = def.getRightOp();
                //如果存在字段引用，就把字段事实加入进去
                if((rval instanceof FieldRef) && (fieldFact.containsKey(((FieldRef) rval).getField())))
                {
                    Set<DefinitionStmt> ff = fieldFact.get(((FieldRef) rval).getField());
                    pDefs.addAll(ff);
                }
                else if((rval instanceof FieldRef) && (fieldFact.containsKey(((FieldRef) rval).getField())))
                {//暂不考虑
//                    val fFacts = onTheFlyFieldFactFor(rval.field)
//                    refinedResults[unit]!!.addAll(fFacts)
                    System.out.println("fly");
                }
                else
                {
                    pDefs.add(def);
                }
            }
            refinedResults.put(p.getKey(),pDefs);
        }
        if(refinedResults.isEmpty() && solver.id == SunnySolver.id)//hashCode??
            return onTheFlyStrDataflowFactAt(stmt);
        return refinedResults;

    }

    private static Map<Value, Set<DefinitionStmt>> onTheFlyStrDataflowFactAt(Stmt stmt) {
        //方法间控制流分析，
        SootMethod m = icfg.getMethodOf(stmt);
        if(!otfSolvers.containsKey(m))
        {
           //"starting on-the-fly SA solving for $m")
            Unit entry = m.getActiveBody().getUnits().getFirst();
            RDprblem otfProblem = new RDprblem(icfg, fieldFact, entry,false);
            JimpleIFDSSolver<Pair<Value, Set<DefinitionStmt>>, InterproceduralCFG<Unit, SootMethod>> otfSolver = new JimpleIFDSSolver<>(otfProblem);
            otfSolver.solve();
            otfSolvers.put(m,new StringFactSolver(otfProblem, otfSolver));
        }
        return strDataflowFactAt(stmt, otfSolvers.get(m));
    }

    @Override
    protected void internalTransform(String s, Map<String, String> map) {
        SootClass sootClass = Scene.v().loadClass("dummyMainClass", SootClass.BODIES);
        SootMethod sootMethod = sootClass.getMethodByName("dummyMainMethod");
        Unit entrypoint = sootMethod.getActiveBody().getUnits().getFirst();//dummyMainClass.dummyMainMethod.activebody.units.first作为入口点
        icfg = new JimpleBasedInterproceduralCFG();

        RDprblem rdProblem = new RDprblem(icfg,fieldFact, entrypoint,false);
        //使用IFDS求解器Heros来解决problem,createZeroValue和initialSeeds被完成了
        JimpleIFDSSolver<Pair<Value,Set<DefinitionStmt>>, InterproceduralCFG<Unit, SootMethod>> solver = new JimpleIFDSSolver<>(rdProblem);
        solver.solve();
        //SunnySolver会被用在对check和request的检查中
        SunnySolver = new StringFactSolver(rdProblem,solver);

    }
}

class StringFactSolver{

    RDprblem problem;
    JimpleIFDSSolver<Pair<Value,Set<DefinitionStmt>>, InterproceduralCFG<Unit, SootMethod>> solver;
    int id;
    public StringFactSolver(RDprblem problem, JimpleIFDSSolver<Pair<Value, Set<DefinitionStmt>>, InterproceduralCFG<Unit, SootMethod>> solver) {
        this.problem = problem;
        this.solver = solver;
        this.id = solver.hashCode();
    }
}


