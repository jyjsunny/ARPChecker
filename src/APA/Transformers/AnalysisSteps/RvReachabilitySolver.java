package APA.Transformers.AnalysisSteps;

import APA.Transformers.Config;
import soot.*;
import soot.jimple.*;
import soot.toolkits.graph.DominatorsFinder;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.toolkits.graph.SimpleDominatorsFinder;
import soot.toolkits.graph.UnitGraph;
import soot.toolkits.scalar.LocalDefs;

import java.io.InvalidObjectException;
import java.util.*;

public class RvReachabilitySolver {
    private final Body body;
    private final UnitPatchingChain units;
    private final UnitGraph cfg ;
    private final DominatorsFinder<Unit> analysis;
    private final LocalDefs localDefs;

    public RvReachabilitySolver(SootMethod method) {
        this.body= method.getActiveBody();
        this.units = this.body.getUnits();
        this.cfg = new ExceptionalUnitGraph(this.body);
        this.analysis = new SimpleDominatorsFinder<Unit>(cfg);//SimpleDominatorsFinder，通过函数内部的控制流分析构建一个简单的支配者搜索器
        this.localDefs = LocalDefs.Factory.newLocalDefs(body);//method中对于局部变量的新定义
    }

    public Set<Integer> solveAvailableRvs(Stmt callsite, Set<Integer> initRv) throws InvalidObjectException {
        //require(callsite in units)
        List<Unit> dominators = analysis.getDominators(callsite);//得到callsite的所有分配者
        List<Unit> constrains = new ArrayList<>();
        for(Unit u:dominators)
        {
            if(isRvChecker(u))//找到callsite所有分配者中包含RV检查的语句的uint（这里的unit语句为在最初rvs范围上的限制）
                constrains.add(u);
        }
        Set<Integer> rvs = initRv;
        Set<Integer> res = new HashSet<>();
        for(Unit cond:constrains)//遍历所有的限制语句（条件判断语句）
        {
            //check(cond is IfStmt && cond.condition is ConditionExpr)
            ConditionExpr constrain = (ConditionExpr) ((IfStmt)cond).getCondition();
            Stmt positive = ((IfStmt)cond).getTarget();//if==true要走的下一个语句
            Stmt negative = (Stmt) units.getSuccOf(cond);//if==false要走的下一个语句
            //check(positive != negative)
            for(int it:rvs)
            {
                boolean rightConst = constrain.getOp2() instanceof Constant;//得到ConditionExpr右边第二个操作数是否属于常量？
                boolean followGoto = rvSatisfy(it, constrain, rightConst);//查看constrain是否满足true的条件
                if(followGoto) {
                    // reachable from positive to callsite
                    LinkedList<Unit> stack  = new LinkedList<>();
                    stack.add((Unit)positive);
                    if(simpleReachable(stack, callsite))//如果从stack对应的语句最终能到达callsite
                        res.add(it);
//                    positive in dominators
                }
                else {
                    // reachable from negative to callsite
                    LinkedList<Unit> stack = new LinkedList<>();
                    stack.add((Unit)negative);
                    if(simpleReachable(stack, callsite))
                        res.add(it);
//                    negative in dominators
                }
            }

        }
        return res;

    }

    private boolean simpleReachable(LinkedList<Unit> stack, Stmt tgt) {
        Unit front = stack.peek();//Retrieves, but does not remove, the head (first element) of this list.
        for(Unit it:cfg.getSuccsOf(front))
        {
            if(it == tgt)
                return true;
            if(!stack.contains(it))
                stack.push(it);
            if(simpleReachable(stack, tgt))
                return true;
            stack.pop();
        }
        return false;
    }

    private boolean rvSatisfy(int rv, ConditionExpr constrain, boolean rightConst) throws InvalidObjectException {
        if(rightConst)
        {
            IntConstant constant = (IntConstant)constrain.getOp2();
//            System.out.println(rv);
//            System.out.println(" "+constant.value);
            if(constrain instanceof LtExpr)//??
                return rv < constant.value;
            else if(constrain instanceof LeExpr)
                return rv <= constant.value;
            else if(constrain instanceof GtExpr)
                return rv > constant.value;
            else if(constrain instanceof GeExpr)
                return rv >= constant.value;
            else if(constrain instanceof NeExpr)
                return rv != constant.value;
            else if(constrain instanceof EqExpr)
                return rv == constant.value;
            else
                throw new InvalidObjectException("unknown cond type: ${constrain.javaClass}");
        }
        else {
            IntConstant constant = (IntConstant)constrain.getOp1();
            if(constrain instanceof LtExpr)
                return constant.value < rv;
            else if(constrain instanceof LeExpr)
                return constant.value <= rv;
            else if(constrain instanceof GtExpr)
                return constant.value > rv;
            else if(constrain instanceof GeExpr)
                return constant.value >= rv;
            else if(constrain instanceof NeExpr)
                return constant.value != rv;
            else if(constrain instanceof EqExpr)
                return constant.value == rv;
            else
                throw new InvalidObjectException("unknown cond type: ${constrain.javaClass}");
        }
    }

    private boolean isRvChecker(Unit unit) {
        if(!(unit instanceof IfStmt && ((IfStmt) unit).getCondition() instanceof ConditionExpr)) {
            return false;
        }
        ConditionExpr cond = (ConditionExpr) ((IfStmt) unit).getCondition();
        Value left = cond.getOp1();
        Value right = cond.getOp2();
        List<Unit> def = null;

        if(left instanceof Local && left.getType() instanceof IntType && right instanceof IntConstant)
            def = localDefs.getDefsOfAt((Local) left, unit);
        else if(right instanceof Local && right.getType() instanceof IntType && left instanceof IntConstant)
            def = localDefs.getDefsOfAt((Local) right, unit);//得到在if这一语句中local变量A的所在的全部unit
        Unit flag =null;
        if(def!=null) {
            for (Unit u : def) {
                if (u instanceof AssignStmt) {
                    Value rop = ((AssignStmt) u).getRightOp();//得到该local变量A被赋值的语句是否=="<android.os.Build$VERSION: int SDK_INT>"
                    if ((rop instanceof FieldRef) && (Objects.equals(((FieldRef) rop).getField().getSignature(), Config.SDK_INT_FIELD)))
                        flag = u;
                }
            }
        }
        return flag != null;

    }



























}
