package APA.Transformers.AnalysisSteps;

import APA.Transformers.CFG;
import APA.Transformers.Config;
import APA.Transformers.ManualOp.DoFiles;
import APA.Transformers.ManualOp.StepReport;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.PermissionRelate.PermissionCombination;
import APA.Transformers.Tri;
import APA.Transformers.Type1Transformers.BillTransformer;
import APA.Transformers.apiRelate.api;
import APA.Transformers.apiRelate.apiMethod;
import javafx.util.Pair;
import soot.*;
import soot.jimple.*;
import soot.jimple.internal.JEqExpr;
import soot.jimple.internal.JIfStmt;
import soot.jimple.internal.JNeExpr;
import soot.jimple.internal.JimpleLocal;
import soot.toolkits.graph.Block;
import soot.toolkits.graph.BlockGraph;
import soot.toolkits.graph.UnitGraph;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

public class SynchronousAnalyzer {
    private static final int   PERMISSION_DENIED = -1;
    private static final int  PERMISSION_GRANTED = 0;

    public static Map<String,Set<BestPracticeFollowType>> synchronousAnalyze(Set<StepReport> reports) throws IOException {
        Map<String, List<String>> stepReport = new HashMap<>();//用于存储report中declare、check、request、handle数量
        Map<String,Set<BestPracticeFollowType>> syncReport = new HashMap<>();//用于存储危险调用脸包含的BestPracticeFollowTypes
        for(StepReport report :reports)
        {
            Map<Permission,Set<BestPracticeFollowType>> followTypes = new HashMap<>();
            LinkedList<String> desc = new LinkedList<>();
            for(Permission p :report.permissions)
            {
                followTypes.put(p,analyzeFollowType(p,report));
                desc.add(p+" declared= "+report.declareRes.get(p)+" with "+report.checkRes.get(p).size()+"--CHECK/"+report.requestRes.get(p).size()+"--REQUEST/"+report.handleRes.get(p).size()+"--HANDLE/");
            }
            Path storePath = Config.apkOutputDir.resolve("Reports").resolve(report.count+"-"+apiMethod.printApiMethod(report.api)+".txt").toAbsolutePath();
            stepReport.put(storePath.toString(),desc);

            // aggregate results
            Set<BestPracticeFollowType> agg = aggregateFollowTypes(report.api, followTypes);
            syncReport.put(storePath.toString(),agg);
        }

        List<String> r = new ArrayList<>();
        for(Map.Entry<String, Set<BestPracticeFollowType>> syncmap :syncReport.entrySet())
        {
            StringBuilder result = new StringBuilder();
            result.append(syncmap.getKey());
            result.append("\n");
            result.append("{");
            for(BestPracticeFollowType bt:syncmap.getValue())
            {
                result.append(bt.typeName);
                result.append(",");
            }
            result.append("}\n");
            StringBuilder detail = new StringBuilder();
            for(String s:stepReport.get(syncmap.getKey()))
            {
                detail.append(s);
                detail.append("\n");
            }
            detail.append("\n\n----\n");

            r.add(result.toString()+detail);
        }


        DoFiles.writeListTo(r, "syncreport.txt");

        return syncReport;
    }

    private static Set<BestPracticeFollowType> aggregateFollowTypes(apiMethod api, Map<Permission, Set<BestPracticeFollowType>> follow)
    {
        Set<BestPracticeFollowType> result = new HashSet<>();//合并当前api的所有permissoin的followType
        for(Map.Entry<Permission, Set<BestPracticeFollowType>> f : follow.entrySet())
        {
            for(BestPracticeFollowType b:f.getValue())
            {
                if(!result.contains(b))
                    result.add(b);
                else
                    ;
            }
        }
        PermissionCombination pc = PermissionCombination.get(api);
        if(pc == PermissionCombination.AnyOf){//疑问：这里每个permission对应的结果不同，怎么对应上去？
            if(result.contains(BestPracticeFollowType.PermissionNotDeclared) && result.size() > 1)
                result.remove(BestPracticeFollowType.PermissionNotDeclared);
            // AnyOf permission is ok, so choose the positive one
            if(result.contains(BestPracticeFollowType.CheckedInSequence) && result.contains(BestPracticeFollowType.CheckNotInSequence))
            {
                result.remove(BestPracticeFollowType.CheckNotInSequence);    // remove!
            }
            if(result.contains(BestPracticeFollowType.RequestedInSequence) && result.contains(BestPracticeFollowType.RequestNotInSequence)) {
                result.remove(BestPracticeFollowType.RequestNotInSequence);
            }
            if(result.contains(BestPracticeFollowType.OverrideFallbackWithHandle) && result.contains(BestPracticeFollowType.OverrideFallbackNoHandle))
            {
                result.remove(BestPracticeFollowType.OverrideFallbackNoHandle);
            }
        }
        if(pc == PermissionCombination.AllOf){
            if(result.contains(BestPracticeFollowType.PermissionNotDeclared) && result.size()> 1)
                return Collections.singleton(BestPracticeFollowType.PermissionNotDeclared);
            // here use the assumption that each permission has either `In` xor `NotIn`
            if(result.contains(BestPracticeFollowType.CheckedInSequence) && result.contains(BestPracticeFollowType.CheckNotInSequence)) {
                result.remove(BestPracticeFollowType.CheckedInSequence);    // remove!
            }
            if(result.contains(BestPracticeFollowType.RequestedInSequence) && result.contains(BestPracticeFollowType.RequestNotInSequence)) {
                result.remove(BestPracticeFollowType.RequestedInSequence);
            }
            if(result.contains(BestPracticeFollowType.OverrideFallbackWithHandle) && result.contains(BestPracticeFollowType.OverrideFallbackNoHandle))
            {
                result.remove(BestPracticeFollowType.OverrideFallbackWithHandle);
            }
        }
        return result;
    }

    public static Set<BestPracticeFollowType> analyzeFollowType(Permission p, StepReport report) {
        Boolean pdeclare = false;
        List<CheckSite> pcheck = new ArrayList<>();
        List<RequestSite> prequest = new ArrayList<>();
        List<SootMethod> phandle = new ArrayList<>();
        for(Map.Entry<Permission,Boolean> pd:report.declareRes.entrySet())
        {
            if(Objects.equals(pd.getKey().toString(), p.toString()))
                pdeclare = pd.getValue();
        }
        for(Map.Entry<Permission,List<CheckSite>> pc:report.checkRes.entrySet())
        {
            if(Objects.equals(pc.getKey().toString(), p.toString()))
                pcheck = pc.getValue();
        }
        for(Map.Entry<Permission,List<RequestSite>> pr:report.requestRes.entrySet())
        {
            if(Objects.equals(pr.getKey().toString(), p.toString()))
                prequest = pr.getValue();
        }
        for(Map.Entry<Permission,List<SootMethod>> ph:report.handleRes.entrySet())
        {
            if(Objects.equals(ph.getKey().toString(), p.toString()))
                phandle = ph.getValue();
        }

        boolean overrideHandle = (!phandle.isEmpty()) && (!api.isSupport(phandle.get(0)));//非空，并且头部方法非supportList成员？？猜测：重写回调
        if(!pdeclare) {
            return Collections.singleton(BestPracticeFollowType.PermissionNotDeclared);
        }
        else if(pcheck.isEmpty() && prequest.isEmpty() && !overrideHandle) {
            return Collections.singleton(BestPracticeFollowType.OnlyDeclared);
        }
        else{
            Set<BestPracticeFollowType> types = new HashSet<>();
            //Check，先判断有没有检查
            if(!pcheck.isEmpty())//如果有Permission p有CheckSite
            {
                for(CheckSite c:pcheck)
                {
                    SootMethod caller = Scene.v().getMethod(apiMethod.printSignature(report.chain.get(c.i)));//找到callChain中调用了check的caller
                    SootMethod apiCaller = Scene.v().getMethod(apiMethod.printSignature(report.chain.get(c.i+1)));//以及包含apiMethod的方法
                    if(synchonouslyCheckedBefore(caller, c.checker, apiCaller))
                    {
                        // only keep the **in** type
                        types.add(BestPracticeFollowType.CheckedInSequence);
                    }
                }

                if(!types.contains(BestPracticeFollowType.CheckedInSequence))
                    types.add(BestPracticeFollowType.CheckNotInSequence);
            }
            else {
                types.add(BestPracticeFollowType.NoCheck);
            }
            //Request，在判断是不是检查之后再请求的
            if(!prequest.isEmpty())
            {
                for(RequestSite r:prequest)
                {
                    SootMethod caller = Scene.v().getMethod(apiMethod.printSignature(report.chain.get(r.i)));
                    if(synchonouslyCheckedThen(caller, r.requester))
                    {
                        types.add(BestPracticeFollowType.RequestedInSequence);
                    }
                }
                if(types.contains(BestPracticeFollowType.RequestedInSequence))
                    types.add(BestPracticeFollowType.RequestNotInSequence);
            }
            else
            {
                types.add(BestPracticeFollowType.NoRequest);
            }
            //handle_api，
            if(apiMethod.printSignature(report.chain.get(0)).equals(Config.HANDLE_API)) {
                //protected-API 在 HANDLE 内部调用，因此无需检查或请求，只需调用它即可。
                // 另，必须重新实现 HANDLE，因此 overrideHandle 的值必须为 true
                if(overrideHandle)////如果第一个方法就是HANDLE_API，并且不是supportList中的（即重新实现了）
                {
                    SootMethod entry = Scene.v().getMethod(apiMethod.printSignature(report.chain.get(0)));
                    SootMethod dcaller = Scene.v().getMethod(apiMethod.printSignature(report.chain.get(1)));
                    if(invokeWithCorrectHandle(entry, dcaller) || types.contains(BestPracticeFollowType.CheckedInSequence))
                        types.add(BestPracticeFollowType.HandledInSequence);
                    else
                        types.add(BestPracticeFollowType.HandleNotInSequence);
                }

            }
            //override Handle
            if(overrideHandle) {//如果后续存在handleApi
                for(SootMethod ph:phandle)//并且ph有body，那么就算是handlebody重写了
                {
                    //usePermissionInHandle(ph, p)
                    if(ph.hasActiveBody()){
                        types.add(BestPracticeFollowType.OverrideFallbackWithHandle);
                    }
                }
                if(!types.contains(BestPracticeFollowType.OverrideFallbackWithHandle))
                    types.add(BestPracticeFollowType.OverrideFallbackNoHandle);
            }
            else {
                types.add(BestPracticeFollowType.UseFallbackHandle);
            }

            return types;
        }

    }

    private static boolean invokeWithCorrectHandle(SootMethod method, SootMethod caller) {
        UnitGraph cfg = CFG.getUnitGraph(method);
        if(cfg != null)
        {
            //findAllValidIfStmts(): Iterator<IfStmt>
            List<IfStmt> findAllValidIfStmts = new ArrayList<>();//用于存储method中所有包含check的IfStmt
            for(Unit u:method.getActiveBody().getUnits())
            {
                if(u instanceof IfStmt && ((IfStmt) u).getCondition() instanceof ConditionExpr)
                {//如果method中的 当前unit属于IfStmt，并且unit的condition属于conditionExpr
                    if(Objects.equals(((ConditionExpr) ((IfStmt) u).getCondition()).getOp1().getType().toString(), "int"))
                    {//并且该uint的conditionExpr的第一个操作数是int型
                        IfStmt ifstmt = (IfStmt) u;
                        if(isCheckForResult(method,ifstmt))//如果ifstmt中的local存在在之前语句与数组变量的重定义
                        {
                            findAllValidIfStmts.add(ifstmt);//那么就是合法ifStmt
                        }
                    }
                }
            }
            //
            Iterator<IfStmt> itfindAllValidIfStmts = findAllValidIfStmts.iterator();
            while(itfindAllValidIfStmts.hasNext())
            {
                IfStmt ifstmt = itfindAllValidIfStmts.next();
                Stmt takeBranch = ifstmt.getTarget();
                Unit failBranch = null;
                for(Unit u:cfg.getSuccsOf(ifstmt))
                {
                    if(u!=ifstmt.getTarget()) {//如果u！=if成立时对应的下一个unit，则
                        failBranch = u;//那么进入else
                        break;
                    }
                }
                Unit grantedBranch;//根据IfStmt的语句条件状态确定下一句branch是：if的下一句/else
                if(takeIsGranted(ifstmt))
                    grantedBranch = takeBranch;
                else
                    grantedBranch = failBranch;
                //如果在unit：grantedBranch之后存在chain中下一个方法的调用，即在method和caller之间存在重新定义的IfStmt
                if(invokeAfter(cfg,caller, grantedBranch))
                    return true;

            }
        }
        return false;
    }

    private static boolean invokeAfter(UnitGraph cfg,SootMethod m, Unit unit) {
        LinkedList<Unit> stack = new LinkedList<>();
        stack.push(unit);
        while(!stack.isEmpty())
        {
            Unit cur = stack.pop();
            if(cur instanceof Stmt)
            {
                if( ((Stmt) cur).containsInvokeExpr()&& ((Stmt) cur).getInvokeExpr().getMethod() == m)
                    return true;
            }
            for(Unit un:cfg.getSuccsOf(cur))
            {
                stack.push(un);
            }
        }
        return false;
    }

    private static boolean isCheckForResult(SootMethod method,IfStmt ifs) {
        List<ValueBox> ifcond = ifs.getCondition().getUseBoxes();
        //如果ifs中某一个局部变量之前被重定义过，且重定义语句中包含数组调用，并且这个数组被定义过，则返回true
        for(ValueBox vb: ifcond)//遍历IfStmt的状态的useBoxes
        {
            if(vb.getValue() instanceof Local)
            {
                Local local = (Local) vb.getValue();
                //得到local变量在到达method中的stmt之前被定义过的units
                List<Unit> cdfact = BillTransformer.handleRdFactAt(method, local, (Stmt) ifs);
                for(Unit u:cdfact)
                {
                    if(u instanceof AssignStmt)
                    {
                        if(((AssignStmt) u).getRightOp() instanceof ArrayRef)//如果重定义stmt的右操作数是数组引用
                        {
                            AssignStmt assign = (AssignStmt) u;
                            JimpleLocal base = (JimpleLocal) ((ArrayRef)(assign.getRightOp())).getBase();
                            List<Unit> arrfact = BillTransformer.handleRdFactAt(method, base, ifs);//那么就获得数组base在ifs语句之前存在重定义的所有units
                            for(Unit ua:arrfact)
                            {
                                if(ua instanceof IdentityStmt)//对于所有这些重定义语句，如果属于IdentityStmt定义语句
                                    return true;
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    private static boolean synchonouslyCheckedThen(SootMethod caller, SootMethod requester) {
        //判断是否是检查完之后请求的
        List<Pair<Block,Unit>> findAllValidChecks = new ArrayList<>();
        Iterator<Tri> itF = CFG.findAllCallsites(caller);//首先找到caller中的所有call站点：Tri(block,unit,invoke)
        if(itF != null) {
            while (itF.hasNext()) {
                Tri tri = itF.next();
                //找到callSites中所有包含check_API的位置
                if (Config.CHECK_APIS.contains(tri.invoke.getMethod().getSignature())) {
                    findAllValidChecks.add(new Pair<>(tri.block, tri.unit));
                }

            }
        }
        BlockGraph cfg = CFG.getGraph(caller);
        if(cfg != null)
        {
            Iterator<Pair<Block,Unit>> itfindAllValidChecks = findAllValidChecks.iterator();
            while(itfindAllValidChecks.hasNext())
            {
                Pair<Block,Unit> p = itfindAllValidChecks.next();
                // jif 可能来自下一个只有一个 stmt 的块
                //通过当前checksite的所在block和unit，返回当前block中unit的下一个JIfStmt，或者如果没有的话，就返回后续block中的第一个IfStmt的block
                Pair<Block, JIfStmt> nbjif = getNextJIfStmt(cfg, p.getKey(),p.getValue());//增加对If语句对判断
                Block takeBranch = null;
                if(nbjif != null) {
                    for (Block b : cfg.getSuccsOf(nbjif.getKey()))//遍历包含IfStmt的后续block
                    {
                        if(Objects.equals(b.getHead().toString(), nbjif.getValue().toString()))//如果某个block的头部IfStmt==checkBlock的Ifstmt
                        {
                            takeBranch = b;//用于存储后续block中第一个包含checkSite中block的Ifstmt的block
                            break;
                        }
                    }
                }
                Block failBranch = null;
                if(nbjif != null) {
                    for (Block b : cfg.getSuccsOf(nbjif.getKey()))
                    {
                        if(b.getIndexInMethod()== nbjif.getKey().getIndexInMethod()+1)//如果b的block序号==nbjif的block序号+1，即不存在block调用
                        {
                            {
                                failBranch = b;
                                break;
                            }
                        }
                    }
                }
                Block elseBlock = null;
                if(nbjif != null){
                    if (takeIsGranted(nbjif.getValue()))////如果ifStmt的状态是Eq，且无常量
                        elseBlock = failBranch;//直接是顺序的下一个block
                    else
                        elseBlock = takeBranch;//如果不是，则elseBlock=
                }
                if(elseBlock != null)//用于存储Ifstmt下一个要走的block
                    return requesterReachable(elseBlock, requester);
            }
        }
        return false;
    }

    private static boolean requesterReachable(Block block, SootMethod requester) {
        LinkedList<Block> queue = new LinkedList<>(Collections.singleton(block));
        HashSet<Integer> visited = new HashSet<>();

        while(!queue.isEmpty())
        {
            Block cur = queue.removeFirst();
            visited.add(block.getIndexInMethod());
            Iterator<Pair<Unit, InvokeExpr>> itP = CFG.findAllCallsites(cur);//找到当前block：cur中的所有CallSites
            while(itP.hasNext())
            {
                Pair<Unit, InvokeExpr> p = itP.next();
                if(Objects.equals(p.getValue().getMethod().getSignature(), requester.getSignature()))//如果调用站点调用的方法==requester的方法
                    return true;
            }
            //如果调用站点的方法没有包含requester的，就遍历后续的blocks
            for(Block u:cur.getSuccs())
            {
                if(!visited.contains(u.getIndexInMethod()))
                    queue.addLast(u);
            }
        }
        return false;
    }

    private static boolean takeIsGranted(IfStmt jif) {
        Value cond = jif.getCondition();//获取jifStmt语句的状态
        ValueBox intBox = null;
        for(ValueBox vb:cond.getUseBoxes())
        {
            if(vb.getValue() instanceof IntConstant)
            {
                intBox = vb;//找到jif语句中的第一个常量box
                break;
            }

        }
        IntConstant intConst = (IntConstant) intBox.getValue();
        if(cond instanceof JEqExpr)//如果是JEqExpr语句，且无常量，则返回true？？？
            return intConst.value == PERMISSION_GRANTED;//0
        else if(cond instanceof JNeExpr)//如果是JNeExpr语句，则返回false？？？
            return intConst.value == PERMISSION_DENIED;//-1
        else
            return false;
    }

    private static Pair<Block, JIfStmt> getNextJIfStmt(BlockGraph cfg, Block block, Unit unit) {
        //返回在block中unit的下一个unit，或者如果没有的话，就返回该block的后续block中头部unit属于IfStmt的block
        Pair<Block, JIfStmt> res;
        try
        {
            return new Pair<>(block, (JIfStmt) block.getSuccOf(unit));
        } catch (ClassCastException ex) {
            Block nb=null;
            for(Block b:cfg.getSuccsOf(block))
            {
                if(b.getHead() instanceof IfStmt)
                {
                    nb=b;
                    break;
                }
            }
            if(nb==null)
                return null;
            return new Pair<>(nb, (JIfStmt)nb.getHead());
        }
    }


    private static boolean synchonouslyCheckedBefore(SootMethod caller, SootMethod checker, SootMethod apiCaller) {
        boolean isChecked = false;
        Iterator<Block> itB = CFG.flowIterator(caller);//itB用于存储caller方法体内根据cfg得到的 block的流调用顺序
        while(itB.hasNext())
        {
            Block block = itB.next();
            Iterator<Pair<Unit, InvokeExpr>> itC = CFG.findAllCallsites(block);//itC：存储block内所有包含调用的unit
            while(itC.hasNext())
            {
                Pair<Unit, InvokeExpr> p = itC.next();
                //在apiCaller之前检查了check（即isChecked是true）
                if(Objects.equals(p.getValue().getMethod().getSignature(), checker.getSignature()))
                    isChecked = true;
                else if(Objects.equals(p.getValue().getMethod().getSignature(), apiCaller.getSignature()) && isChecked)
                    return true;
            }
        }

        return false;
    }
}
