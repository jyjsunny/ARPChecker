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
            //???????????????????????????method???invoke
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
        ExceptionalBlockGraph cfg = new ExceptionalBlockGraph(method.getActiveBody());//??????method???cfg
        Map<Integer,Integer> inDeg = calcInDegreeWithoutBack(cfg);//??????method???cfg?????????block??????????????????
        TreeSet<Integer> visited = new TreeSet<>();

        LinkedList<Integer> queue = new LinkedList<>();
        for(Block b:cfg.getHeads())//???cfg??????????????????block???????????????queue?????????
        {
            queue.add(b.getIndexInMethod());
        }
        while(!queue.isEmpty())
        {
            Integer hidx = queue.removeFirst();
            if(inDeg.get(hidx) == 0)//?????????????????????block?????????0?????????????????????????????????
            {
                Block head = cfg.getBlocks().get(hidx);
                itB.add(head);//head???????????????itB?????????
                visited.add(hidx);
                for(Block b:head.getSuccs())//????????????head block?????????blocks
                {
                    Integer idx = b.getIndexInMethod();
                    inDeg.put(idx,inDeg.get(idx)-1);//????????????????????????head?????????block
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
        Map<Integer, Integer> inMap = new HashMap<>();//????????????method???blockGraph???????????????block??????????????????
        for(Block b:cfg)
        {
            inMap.put(b.getIndexInMethod(),b.getPreds().size());//??????block??????????????????
        }
        //dfs???u???????????????0???dfs??????????????????back??????????????????degree
        dfs(inMap,cfg,cfg.getHeads().get(0).getIndexInMethod(), new HashSet(), new HashSet());//??????????????????
        return inMap;

    }
    public static void dfs(Map<Integer, Integer> inMap,BlockGraph cfg,int u, Set<Integer> instk, Set<Integer> vis)
    {//, map:MutableMap<Int,Int>) {
        instk.add(u);
        vis.add(u);
        for(Block b:cfg.getBlocks().get(u).getSuccs())//??????u?????????block?????????block
        {
            int v= b.getIndexInMethod();//v???block b???cfg????????????
            if(vis.contains(v) && instk.contains(v))//????????????????????????????????????????????????v
            {
                // (u,v) is a back edge
                inMap.put(v,inMap.get(v)-1);//??????back?????????v?????????-1
            }
            else if(!vis.contains(v))
            {
                dfs(inMap,cfg,v, instk, vis);//???????????????block???????????????
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
