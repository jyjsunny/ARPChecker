package APA.Transformers;

import APA.Transformers.AnalysisSteps.*;
import APA.Transformers.ManualOp.RevStepReport;
import APA.Transformers.ManualOp.StepReport;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.Type1Transformers.SunnyTransformer;
import APA.Transformers.apiRelate.MaintainingAPI;
import APA.Transformers.apiRelate.PCallChain;
import APA.Transformers.apiRelate.apiMethod;

import com.sun.codemodel.internal.JMethod;
import javafx.util.Pair;
import soot.Scene;
import soot.SootMethod;

import java.nio.file.Path;
import java.util.*;

public class HBReport {
    public apiMethod api;
    public List<apiMethod> chain;
    public Path storePath;
    public Set<BestPracticeFollowType> syncType = new HashSet<>();
    public Set<HappenBeforeFollowType> asyncType = new HashSet<>();
    public List<PCallChain> syncCheck = new ArrayList<>();
    public List<PCallChain> syncRequest = new ArrayList<>();
    public List<PCallChain> asyncCheck = new ArrayList<>();
    public List<PCallChain> asyncRequest = new ArrayList<>();

    public HBReport(apiMethod api, List<apiMethod> chain, Path storePath) {
        this.api = api;
        this.chain = chain;
        this.storePath = storePath;
    }

    public static List<HBReport> aggregate(Set<StepReport> reports, RevStepReport revreport, Map<String, Set<BestPracticeFollowType>> sync, Map<String, Set<Pair<HappenBeforeFollowType, Set<PCallChain>>>> async) {
        List<HBReport> hbRes = new ArrayList<>();
        for(StepReport report:reports)
        {
            Path storePath = Config.apkOutputDir.resolve("Reports").resolve(report.count+"-"+ apiMethod.printApiMethod(report.api)+".txt").toAbsolutePath();
            Set<BestPracticeFollowType> syncresult = sync.get(storePath.toString());
            Set<Pair<HappenBeforeFollowType, Set<PCallChain>>> asyncresult = async.get(storePath.toString());

            HBReport hb = new HBReport(report.api, report.chain, storePath);

            hb.syncType = syncresult;

            for(Pair<HappenBeforeFollowType, Set<PCallChain>> pa:asyncresult)
            {
                if(pa.getKey()!=null)
                {
//                    System.out.println(pa.getKey().typeName);
//                    System.out.println(pa.getKey());
                    hb.asyncType.add(new HappenBeforeFollowType(pa.getKey().typeName));
                }
            }
//(1)同步check+request结果存储
            //chk
            List<List<CheckSite>> chk = new ArrayList<>();
            for(Map.Entry<Permission, List<CheckSite>> rc:report.checkRes.entrySet())
            {
                chk.add(rc.getValue());
            }
            boolean completeCheck = false;
            for(List<CheckSite> c:chk) {
                for(CheckSite it:c)
                {
                     apiMethod caller = report.chain.get(it.i);

                    // 如果 interproc，第二个指向检查器包装器，否则，检查 api
                    SootMethod checker = it.checker;
                    if(isSupport(checker))
                        EmpiricalAnalyzer.addIntraProcedure(storePath, new MaintainingAPI("C"));
                    else
                        EmpiricalAnalyzer.addInterProcedure(storePath, new MaintainingAPI("C"));

                    completeCheck = true;

                    hb.syncCheck.add(recoverCChain(caller, it));
                }
            }
            //req
            List<List<RequestSite>> req = new ArrayList<>();
            for(Map.Entry<Permission, List<RequestSite>> rq:report.requestRes.entrySet())
            {
                req.add(rq.getValue());
            }
            boolean completeRequest = false;
            for(List<RequestSite> r:req) {
                for(RequestSite it:r)
                {
                    apiMethod caller = report.chain.get(it.i);

                    // 如果 interproc，第二个指向检查器包装器，否则，检查 api
                    SootMethod checker = it.requester;
                    if(isSupport(checker))
                        EmpiricalAnalyzer.addIntraProcedure(storePath, new MaintainingAPI("R"));
                    else
                        EmpiricalAnalyzer.addInterProcedure(storePath, new MaintainingAPI("R"));

                    completeRequest = true;

                    hb.syncRequest.add(recoverRChain(caller, it));
                }
            }
            boolean syncComplete = completeCheck && completeRequest;
 //（2）异步check+request结果存储
            //asynccheck
            apiMethod caller = report.chain.get(0);
            Map<HappenBeforeFollowType, Set<PCallChain>> map = new HashMap<>();
            for(Pair<HappenBeforeFollowType, Set<PCallChain>> p: asyncresult)
            {
                map.put(p.getKey(),p.getValue());
            }
            completeCheck = completeCheck && (apiMethod.printSignature(caller).equals(Config.HANDLE_API));// only this situation, keep the flag
            if(map.containsKey(HappenBeforeFollowType.AsyncCheckBeforeUse)){
                hb.asyncCheck.addAll(map.get(HappenBeforeFollowType.AsyncCheckBeforeUse));
                for(PCallChain it:hb.asyncCheck)
                {
                    apiMethod checker = it.chain.get(0);
                    if(checker.definingClass == caller.definingClass)
                        EmpiricalAnalyzer.addInterLifecycle(storePath, new MaintainingAPI("C"));
                    else
                        EmpiricalAnalyzer.addInterComponent(storePath, new MaintainingAPI("C"));
                }
                completeCheck = true;
            }
            //asyncrequest
            completeRequest = false;
            if(map.containsKey(HappenBeforeFollowType.AsyncRequestBeforeUse)){
                hb.asyncRequest.addAll(map.get(HappenBeforeFollowType.AsyncRequestBeforeUse));
                for(PCallChain it:hb.asyncRequest)
                {
                    apiMethod requester = it.chain.get(0);
                    if(requester.definingClass == caller.definingClass)
                        EmpiricalAnalyzer.addInterLifecycle(storePath, new MaintainingAPI("R"));
                    else
                        EmpiricalAnalyzer.addInterComponent(storePath, new MaintainingAPI("R"));
                }
                completeRequest = true;
            }
            boolean asyncComplete = completeCheck && completeRequest;
            boolean insideHandle = false;
            if(syncresult.contains(BestPracticeFollowType.HandledInSequence))
                insideHandle = true;
            else if(syncresult.contains(BestPracticeFollowType.HandleNotInSequence))
                insideHandle = false;
            else
                insideHandle = false;

            if(!(syncComplete || asyncComplete || insideHandle))
                EmpiricalAnalyzer.addIncomplete(storePath);

            hbRes.add(hb);

        }
        return hbRes;
    }

    private static PCallChain recoverRChain(apiMethod caller, RequestSite rs) {
        List<apiMethod> chain = traceChain(caller, rs.invoke.getMethod());
        Set<Permission> saPermission = SunnyTransformer.concretePermissionValuesAt(rs.unit);
        return new PCallChain(chain, saPermission);
    }

    private static PCallChain recoverCChain(apiMethod caller, CheckSite cs) {
        List<apiMethod> chain = traceChain(caller, cs.invoke.getMethod());
        Set<Permission> saPermission = SunnyTransformer.concretePermissionValuesAt(cs.unit);
        return new PCallChain(chain, saPermission);
    }

    private static List<apiMethod> traceChain(apiMethod caller, SootMethod tgtMethod) {
        List<apiMethod> res = new ArrayList<>();
        LinkedList<SootMethod> stack = new LinkedList<>();
        SootMethod start = Scene.v().getMethod(apiMethod.printSignature(caller));
        stack.addLast(start);
        boolean flag = dfs(stack, new HashSet<>(), 10, tgtMethod);
        if(flag)
        {
            for(SootMethod sm:stack)
            {
                res.add(apiMethod.fromSootSignature(sm.getSignature()));
            }

            return res;
        }
        else
            throw (new IllegalStateException("Check failed."));

    }

    private static boolean dfs(LinkedList<SootMethod> stack, HashSet<SootMethod> visited, int level, SootMethod tgtMethod) {
        if(level == 0)
            return false;
        // last is current
        SootMethod method = stack.getLast();
        if(Objects.equals(method.getSignature(), tgtMethod.getSignature()))
            return true;
        // ugly condition, maybe soot bug
        else if(Objects.equals(tgtMethod.getSignature(), Config.ABS_CHECK) && Objects.equals(method.getSignature(), Config.ALTER_CHECK))
            return true;
        visited.add(method);
        Iterator<SootMethod> itc=CG.getCISCallFrom(method);
        while(itc.hasNext())
        {
            SootMethod child = itc.next();
            if(Objects.equals(child.getSignature(), tgtMethod.getSignature())) {
                stack.addLast(child);
                return true;
            }
            // ugly condition, maybe soot bug
            else if(Objects.equals(tgtMethod.getSignature(), Config.ABS_CHECK) && Objects.equals(child.getSignature(), Config.ALTER_CHECK)){
                stack.addLast(child);
                return true;
            }

            if(visited.contains(child) || isBLACK(child))
                continue;
            stack.addLast(child);
            if(dfs(stack, visited, level-1, tgtMethod))
                return true;
            stack.removeLast();
        }
        return false;

    }

    private static boolean isBLACK(SootMethod child) {
        for(int i = 0; i< Config.BLACK_LIST.size(); i++)
        {
            if(child.getDeclaringClass().getName().startsWith(Config.BLACK_LIST.get(i)))
                return true;
        }
        return false;
    }

    private static boolean isSupport(SootMethod sootMethod) {
        for(int i = 0; i< Config.SUPPORT_LIST.size(); i++)
        {
            if(sootMethod.getDeclaringClass().getName().startsWith(Config.SUPPORT_LIST.get(i)))
                return true;
        }
        return false;
    }


}
