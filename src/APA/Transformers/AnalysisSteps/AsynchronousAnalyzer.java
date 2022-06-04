package APA.Transformers.AnalysisSteps;

import APA.Transformers.CG;
import APA.Transformers.Config;
import APA.Transformers.ManualOp.DoFiles;
import APA.Transformers.ManualOp.RevStepReport;
import APA.Transformers.ManualOp.StepReport;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.CallChain;
import APA.Transformers.apiRelate.PCallChain;
import APA.Transformers.apiRelate.apiClass;
import APA.Transformers.apiRelate.apiMethod;
import com.sun.codemodel.internal.JMethod;
import javafx.beans.binding.ListExpression;
import javafx.util.Pair;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import sun.awt.HKSCS;

import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

public class AsynchronousAnalyzer {
    private static final Map<apiClass,Set<apiClass>> mcg = ModuleCGAnalyzer.getModuleCG();
    private static final List<String> COMPONENT_LIFECYCLE = Arrays.asList(
            "onCreate",
            "onRestart",
            "onStart",
            "onResume",
            // any other methods
            "onPause",
            "onStop",
            "onDestroy"
    );
    private static final double APP_METHOD = COMPONENT_LIFECYCLE.indexOf("onResume") + 0.5;

    public static Map<String, Set<Pair<HappenBeforeFollowType, Set<PCallChain>>>> asynchronousAnalyze(Set<StepReport> reports, RevStepReport revreports) throws IOException {
        Map<String, Set<Pair<HappenBeforeFollowType, Set<PCallChain>>>> asyncReport = new HashMap<>();
        for(StepReport report:reports)
        {
            Set<Permission> needs = report.permissions;
            Map<Permission, Boolean> declared  = new HashMap<>();
            for(Permission p:needs)
            {
                for(Map.Entry<Permission,Boolean> pd:report.declareRes.entrySet())
                {
                    if(Objects.equals(pd.getKey().toString(), p.toString()))
                        declared.put(pd.getKey(),pd.getValue());
                }
            }
            boolean syncChecked = false;//只要其中有一个permission有checksite，那么syncChecked=true；？？？此处认为应该是两个都
            for(Map.Entry<Permission, List<CheckSite>> pd:report.checkRes.entrySet())
            {
                if(!pd.getValue().isEmpty())
                {
                    syncChecked = true;
                    break;
                }
            }
            boolean syncRequested = false;
            for(Map.Entry<Permission, List<RequestSite>> pd:report.requestRes.entrySet())
            {
                if(!pd.getValue().isEmpty())
                {
                    syncRequested = true;
                    break;
                }
            }
            List<PCallChain> checks = new ArrayList<>();//存储对需要permission进行检查的有效checkChains
            for(Map.Entry<apiMethod,Set<PCallChain>> c: revreports.checkMap.entrySet())
            {//如果某条check链所检查的permission包含在需要check的permission中，即有效check链
                for(PCallChain pc:c.getValue())
                {
                    boolean flag =false;
                    for(Permission p:pc.Permissions)
                    {
                        for(Permission p2:needs)
                        {
                            if (Objects.equals(p.toString(), p2.toString())) {
                                flag = true;
                                break;
                            }
                        }
                    }
                    if(flag)
                        checks.add(pc);
                }
            }
            List<PCallChain> requests = new ArrayList<>();//存储对需要permission进行请求的有效requestChains
            for(Map.Entry<apiMethod,Set<PCallChain>> c: revreports.requestMap.entrySet())
            {//如果某条request链所检查的permission包含在需要request的permission中，即有效request链
                for(PCallChain pc:c.getValue())
                {
                    boolean flag =false;
                    for(Permission p:pc.Permissions)
                    {
                        for(Permission p2:needs)
                        {
                            if (Objects.equals(p.toString(), p2.toString())) {
                                flag = true;
                                break;
                            }
                        }
                    }
                    if(flag)
                        requests.add(pc);
                }
            }
            //key=report存储的绝对路径字符串
            String key = Config.apkOutputDir.resolve("Reports").resolve(report.count+"-"+apiMethod.printApiMethod(report.api)+".txt").toAbsolutePath().toString();
            Set<Pair<HappenBeforeFollowType, Set<PCallChain>>> ft = analyzeFollowType(report.chain, declared, checks, requests, syncChecked, syncRequested);
            asyncReport.put(key,ft);
        }
        List<String> r = new ArrayList<>();
        for(Map.Entry<String, Set<Pair<HappenBeforeFollowType, Set<PCallChain>>>> asyncmap : asyncReport.entrySet())
        {
            StringBuilder result = new StringBuilder();
            result.append("\n---\n");
            for(Pair<HappenBeforeFollowType, Set<PCallChain>> hp : asyncmap.getValue())
            {
                result.append(hp.getKey().typeName);
                result.append("\n\t");
                if(hp.getValue()!=null)
                {
                    for(PCallChain p:hp.getValue())
                    {
                        for(apiMethod a:p.chain)
                        {
                            result.append(" -> ");
                        }
                    }
                }
                result.append("\n\t");
                result.append("\n---\n");
            }
            result.append(asyncmap.getKey());
            result.append("\n");
            result.append("\n\n");

            r.add(asyncmap.getKey() + result.toString());
        }


        DoFiles.writeListTo(r, "asyncreport.txt");
        return asyncReport;
    }

    private static Set<Pair<HappenBeforeFollowType, Set<PCallChain>>> analyzeFollowType(List<apiMethod> chain, Map<Permission, Boolean> declared, List<PCallChain> checks, List<PCallChain> requests, boolean syncChecked, boolean syncRequested) {
        if(declared.isEmpty())
        {
            if(checks.isEmpty() && requests.isEmpty())
                return Collections.singleton(new Pair<>(HappenBeforeFollowType.NoDeclareAndNoSteps,null));
            else
                return Collections.singleton(new Pair<>(HappenBeforeFollowType.NoDeclareWithSteps,null));
        }
        else if(checks.isEmpty() && requests.isEmpty()){
            return Collections.singleton(new Pair<>(HappenBeforeFollowType.DeclaredNoSteps,null));
        }

        Map<HappenBeforeFollowType,Set<PCallChain>> types = new HashMap<>();
        if(syncChecked) {
            types.put(HappenBeforeFollowType.SyncCheckedAlready,new HashSet<>());
        }
        else if(apiMethod.printSignature(chain.get(0)).equals(Config.HANDLE_API)) {
            types.put(HappenBeforeFollowType.IsHandleNoCheck,new HashSet<>());
        }
        else {
            for(PCallChain pc:checks)
            {
                if(canHappenBefore(pc.chain,chain))//异步check是否发生在apiChain调用之前
                {
                    if(!types.containsKey(HappenBeforeFollowType.AsyncCheckBeforeUse))
                        types.put(HappenBeforeFollowType.AsyncCheckBeforeUse,new HashSet<>());
                    types.get(HappenBeforeFollowType.AsyncCheckBeforeUse).add(pc);
                }
            }
            if(!types.containsKey(HappenBeforeFollowType.AsyncCheckBeforeUse))
                types.put(HappenBeforeFollowType.NoAsyncCheckBeforeUse,null);

        }

        if(syncRequested){
            types.put(HappenBeforeFollowType.SyncRequestedAlready,new HashSet<>());
        }
        else {
            // obviously, the permission is requested thus HANDLE is invoked
            if (apiMethod.printSignature(chain.get(0)).equals(Config.HANDLE_API)) {
                if (!types.containsKey(HappenBeforeFollowType.AsyncRequestBeforeUse))
                    types.put(HappenBeforeFollowType.AsyncRequestBeforeUse,new HashSet<>());
            }
            for(PCallChain rp:requests) {
                if (canHappenBefore(rp.chain,chain)) {//异步request是否发生在apiChain调用之前
                    if(apiMethod.printSignature(chain.get(0)).equals(Config.HANDLE_API) && !fromTheSameComponent(chain.get(0), rp.chain.get(0)))
                        continue;
                    if (!types.containsKey(HappenBeforeFollowType.AsyncRequestBeforeUse))
                        types.put(HappenBeforeFollowType.AsyncRequestBeforeUse,new HashSet<>());
                    types.get(HappenBeforeFollowType.AsyncRequestBeforeUse).add(rp);
                }
            }
            if (!types.containsKey(HappenBeforeFollowType.AsyncRequestBeforeUse)) {
                types.put(HappenBeforeFollowType.NoAsyncRequestBeforeUse,null);
            }
        }
        Set<Pair<HappenBeforeFollowType, Set<PCallChain>>> res = new HashSet<>();
        for(Map.Entry<HappenBeforeFollowType, Set<PCallChain>> r:types.entrySet())
        {
            res.add(new Pair<>(r.getKey(),r.getValue()));
        }
        return res;
    }

    private static boolean fromTheSameComponent(apiMethod apiMethod1, apiMethod apiMethod2) {
        String apiMethod1Name = apiMethod1.definingClass.name.substring(0,apiMethod1.definingClass.name.indexOf('$'));
        String apiMethod2Name = apiMethod2.definingClass.name.substring(0,apiMethod2.definingClass.name.indexOf('$'));
        return apiMethod1Name.equals(apiMethod2Name);
    }

    private static boolean canHappenBefore(List<apiMethod> chain1, List<apiMethod> chain2) {
        //分别得到chain1和chain2头部api的外部类
        String thisName = getotterClassName(chain1.get(0));
        apiClass thisClass = new apiClass(thisName);
        String thatName = getotterClassName(chain2.get(0));
        apiClass thatClass = new apiClass(thatName);
        if(!thisClass.equals(thatClass)) {//chain1和chain2的外部类不同
            if(isComponent(thisClass) && isComponent(thatClass)){
                // happen-before by ICC-graph
                for(Map.Entry<apiClass,Set<apiClass>> asa : mcg.entrySet())
                {
                    if(asa.getKey()==thisClass)
                    {
                        if(mcg.get(thisClass).contains(thatClass))
                            return true;
                    }
                }
                return false;
            }
            else if(isApplication(thisClass) || isApplication(thatClass)) {
                // the case when only one is application
                if(!isApplication(thisClass) || !isApplication(thatClass))
                    return isApplication(thisClass) && !isApplication(thatClass);
            }
            else if(isComponent(thisClass) && !isComponent(thatClass)) {
                return false;    // for under-estimate
            }
            else if(!isComponent(thisClass) && !isComponent(thatClass)) {
                return false;
            }
            else {
                assert(!isComponent(thisClass) && !isComponent(thatClass));    // dummy assert
                return false;
            }
        }
        else {  // same outter class, analyze by flowdroid dummyMain
            SootMethod thisSootMethod = Scene.v().getMethod(apiMethod.printSignature(chain1.get(0)));
            SootMethod thatSootMethod = Scene.v().getMethod(apiMethod.printSignature(chain2.get(0)));
            if(thisSootMethod == thatSootMethod)
                return false;    // same class, same method, synchronous
            else if(chain1.get(0).definingClass != chain2.get(0).definingClass){
                // in case of anonymous class???
                SootClass thatInnerClass = Scene.v().getSootClass(chain2.get(0).definingClass.name);
                //return isComponent(thisClass) && thatInnerClass.getInterfaces().contains(Config.RUNNABLE_CLASS) && Objects.equals(thatSootMethod.getName(), "run");
                return false;
            }
            return isComponent(thisClass) && lifecycleHappenBefore(thisSootMethod,thatSootMethod);
        }
        return false;
    }

    private static String getotterClassName(apiMethod apiMethod) {
        if(apiMethod.definingClass.name.contains("$"))
            return apiMethod.definingClass.name.substring(0,apiMethod.definingClass.name.indexOf('$'));
        else
            return apiMethod.definingClass.name;
    }

    private static boolean lifecycleHappenBefore(SootMethod thisSootMethod, SootMethod thatSootMethod) {
        String dummyMain = "dummyMainClass:"+thisSootMethod.getDeclaringClass();
        List<SootMethod> thisParent = new ArrayList<>();
        Iterator<SootMethod> its = CG.getCallTo(thisSootMethod);//获取thisSootMethod的所有callMethod
        while(its.hasNext())
        {
            SootMethod sm = its.next();
            if(sm.getSignature().contains(dummyMain))
                thisParent.add(sm);
        }
        List<SootMethod> thatParent = new ArrayList<>();
        Iterator<SootMethod> ita = CG.getCallTo(thatSootMethod);//获取thatSootMethod的所有callMethod
        while(ita.hasNext())
        {
            SootMethod sm = ita.next();
            if(sm.getSignature().contains(dummyMain))
                thatParent.add(sm);
        }
        if(thisParent.isEmpty() || thatParent.isEmpty())//如果thisMethod或者thatMethod都没有入口函数，则false
            return false;
        if(thisParent.size()==1 && thatParent.size()==1)//如果某者有入口函数
        {
            SootMethod thisDummy = thisParent.get(0);
            SootMethod thatDummy = thatParent.get(0);
            if(Objects.equals(thisDummy.getSignature(), thatDummy.getSignature()))//如果入口函数相同
            {
                apiMethod thisApimethod = apiMethod.fromSootSignature(thisSootMethod.getSignature());
                apiMethod thatApimethod = apiMethod.fromSootSignature(thatSootMethod.getSignature());
                return lifecycleHappenBefore(thisApimethod,thatApimethod);
            }
        }
        return false;
    }
    private static boolean lifecycleHappenBefore(apiMethod thisApiMethod, apiMethod thatApiMethod) {
        if (new apiClass(thisApiMethod.definingClass.name.substring(0, thisApiMethod.definingClass.name.indexOf('$'))).equals(new apiClass(thatApiMethod.definingClass.name.substring(0, thatApiMethod.definingClass.name.indexOf('$'))))) {
            int thisIndex = COMPONENT_LIFECYCLE.indexOf(thisApiMethod.methodName);
            int thatIndex = COMPONENT_LIFECYCLE.indexOf(thatApiMethod.methodName);
            if (thisIndex < 0 && thatIndex < 0)
                return true;
            else if (thisIndex < 0 && thatIndex >= 0)
                return thatIndex > APP_METHOD;  // that is in later half
            else if (thisIndex >= 0 && thatIndex < 0)
                return thisIndex < APP_METHOD;
            else
                return thisIndex < thatIndex;
        }
        return false;
    }
    private static boolean isApplication(apiClass thisClass) {
        return thisClass==ManifestAnalyzer.applicationClass;
    }


    private static boolean isComponent(apiClass thisClass) {
        return ModuleCGAnalyzer.cmpNames.contains(thisClass.name);//cmpName用于存储所有模块内的组件名称
    }


}
