package APA.Transformers;

import APA.Transformers.SootRelate.SootBodyUnitVisitor;
import javafx.util.Pair;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.ArrayRef;
import soot.jimple.AssignStmt;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.toolkits.graph.*;

import java.util.*;

import static java.lang.Thread.yield;

public class CFG {
    public static  UnitGraph getUnitGraph(SootMethod sootMethod)
    {
        if(!sootMethod.hasActiveBody())
            return null;
        return new ExceptionalUnitGraph(sootMethod.getActiveBody());
    }
    public static Iterator<Pair<Unit, InvokeExpr>> findAllCallsites(Block block)
    {
        List<Pair<Unit, InvokeExpr>> itP = new ArrayList<>();
        for(Unit unit : block)
        {
            if(unit instanceof Stmt && ((Stmt) unit).containsInvokeExpr())
            {
                itP.add(new Pair<>(unit, ((Stmt) unit).getInvokeExpr()));
            }
        }
        return itP.iterator();
    }
    public static Iterator<Tri> findAllCallsites(SootMethod method)
    {
        if (!method.hasActiveBody())
            return null;
        List<Tri> cubs = new ArrayList<>();
        if (method.hasActiveBody())
        {
            ExceptionalBlockGraph cfg ;
            cfg = new ExceptionalBlockGraph(method.getActiveBody());
            for (Block block: cfg)
            {
                for (Unit unit: block)
                {

                    if (unit instanceof Stmt)
                    {
                        Stmt stmt = (Stmt) unit;
                        if(stmt.containsInvokeExpr())
                        {
                            cubs.add(new Tri(block, unit, stmt.getInvokeExpr()));

                        }
                    }
                }
            }
        }
        return cubs.iterator();
    }

    public static void visitAllStmts(SootMethod method, SootBodyUnitVisitor sootBodyUnitVisitor) {
        if(!method.hasActiveBody())
            return;
        for(Unit unit :new ExceptionalUnitGraph(method.getActiveBody()))
        {
            Stmt stmt = (Stmt) unit;
            //只要语句包含对其他method的invoke
            if(stmt.containsInvokeExpr())
                sootBodyUnitVisitor.visitInvoke(stmt.getInvokeExpr(), stmt);
            if(stmt instanceof AssignStmt && (((AssignStmt) stmt).getLeftOp() instanceof ArrayRef))
                sootBodyUnitVisitor.visitArrayMemberAssign(((ArrayRef)((AssignStmt) stmt).getLeftOp()),((AssignStmt) stmt).getRightOp(),stmt);
        }



    }
    public static Iterator<Block> flowIterator(SootMethod method)//caller
    {
        List<Block> itB = new ArrayList<>();

        if (!method.hasActiveBody())
            return itB.iterator();
        ExceptionalBlockGraph cfg = new ExceptionalBlockGraph(method.getActiveBody());//得到method的cfg
        Map<Integer,Integer> inDeg = calcInDegreeWithoutBack(cfg);//计算method的cfg中每个block的序号和深度
        TreeSet<Integer> visited = new TreeSet<>();

        LinkedList<Integer> queue = new LinkedList<>();
        for(Block b:cfg.getHeads())//从cfg头部开始，将block的序号存入queue链表中
        {
            queue.add(b.getIndexInMethod());
        }
        while(!queue.isEmpty())
        {
            Integer hidx = queue.removeFirst();
            if(inDeg.get(hidx) == 0)//如果当前序号的block深度为0，即是不存在前序调用的
            {
                Block head = cfg.getBlocks().get(hidx);
                itB.add(head);//head作为迭代器itB的头部
                visited.add(hidx);
                for(Block b:head.getSuccs())//遍历这个head block的后续blocks
                {
                    Integer idx = b.getIndexInMethod();
                    inDeg.put(idx,inDeg.get(idx)-1);//更新深度用于存入head后续的block
                    if(inDeg.get(idx)==0)
                        queue.addLast(idx);
                }
            }


        }
        if(visited.size() == cfg.getBlocks().size())
            System.out.println("keyi:visited.size() == cfg.getBlocks().size()");
        //check(visited.size == cfg.blocks.size)  // there are no unvisited block
        return itB.iterator();
    }

    public static Map<Integer, Integer> calcInDegreeWithoutBack(BlockGraph cfg) {
        //require(cfg.heads.size == 1)
        Map<Integer, Integer> inMap = new HashMap<>();//用于遍历method的blockGraph，记录每个block的序号和深度
        for(Block b:cfg)
        {
            inMap.put(b.getIndexInMethod(),b.getPreds().size());//记录block的序号，深度
        }
        //dfs中u的初始化是0，dfs用于删除更新back边导致的错误degree
        dfs(inMap,cfg,cfg.getHeads().get(0).getIndexInMethod(), new HashSet(), new HashSet());//深度优先遍历
        return inMap;

    }
    public static void dfs(Map<Integer, Integer> inMap,BlockGraph cfg,int u, Set<Integer> instk, Set<Integer> vis)
    {//, map:MutableMap<Int,Int>) {
        instk.add(u);
        vis.add(u);
        for(Block b:cfg.getBlocks().get(u).getSuccs())//遍历u所对应block的后续block
        {
            int v= b.getIndexInMethod();//v：block b在cfg中的序号
            if(vis.contains(v) && instk.contains(v))//如果之前访问过，并且当前深度处于v
            {
                // (u,v) is a back edge
                inMap.put(v,inMap.get(v)-1);//存在back边，则v的深度-1
            }
            else if(!vis.contains(v))
            {
                dfs(inMap,cfg,v, instk, vis);//进行下一层block深度的遍历
            }
        }
        instk.remove(u);
    }

    public static BlockGraph getGraph(SootMethod method) {
        if (!method.hasActiveBody())
            return null;
        return new ExceptionalBlockGraph(method.getActiveBody());
    }
}
