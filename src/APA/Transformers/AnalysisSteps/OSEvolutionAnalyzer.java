package APA.Transformers.AnalysisSteps;

import APA.Transformers.ArpMethodMapMap;
import APA.Transformers.Config;
import APA.Transformers.HBReport;
import APA.Transformers.ManualOp.DoFiles;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.PCallChain;
import APA.Transformers.apiRelate.apiMethod;
import javafx.util.Pair;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.tagkit.Tag;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class OSEvolutionAnalyzer {
    private static final int targetMin = Math.max(23, Config.minSdkVersion);
    private static final int targetMax = Config.apkTargetVersion;
    public static void analyzeCompatibility(List<HBReport> hbreports) throws Throwable {
        List<Pair<Path, Map<Integer,EvolutionFollowType>>> pePair = new ArrayList<>();
        //对每一个 hbreport 标记保存 RV Sentinel
        for(HBReport it:hbreports)
        {
            tagRvSentinal(it);//+tag
            Map<SootMethod,RvProtectedCallsite> compat = collectCompatibility(it);
            untagRvSentinal(it);//去tag
            dumpCompat(it.storePath, compat);
            pePair.add(new Pair<>(it.storePath,analyzeHBreport(it, compat)));
        }
        String sep = "-------------------------------------------";
        StringBuilder content = new StringBuilder();
        for(Pair<Path, Map<Integer,EvolutionFollowType>> p:pePair)
        {
            content.append(p.getKey());
            content.append("\n");
            for(Map.Entry<Integer, EvolutionFollowType> map:p.getValue().entrySet())
            {
                content.append(map.getKey());
                content.append(":");
                content.append(map.getValue().typeName);
                content.append("\n");
            }
            content.append("\n");
            content.append(sep);
            content.append("\n");
        }

        DoFiles.writeToFile(content.toString(), "compatreport.txt");
    }

    private static Map<Integer,EvolutionFollowType> analyzeHBreport(HBReport report, Map<SootMethod, RvProtectedCallsite> compat) throws Throwable {
        //逐个遍历HBReport和当前链中方法体内存在的rv check
        Map<Integer,EvolutionFollowType> types = new HashMap<>();
        for(int rv = targetMin;rv<=targetMax;rv++)
        {
            //首先，得到当前rv等级下的Map<apiMethod, Set<Permission>>映射关系
            Map<apiMethod,Set<Permission>> mapping = new HashMap<>();
            mapping = ArpMethodMapMap.getArpMethodMapOf(rv);
            System.out.println("mapping:"+mapping.size());
            //其次，找到当前hbreport对应的危险api需要的权限。
            Set<Permission> dpermission = new HashSet<>();
            for(Map.Entry<apiMethod,Set<Permission>> m:mapping.entrySet())
            {
                if(apiMethod.printSignature(m.getKey()).equals(apiMethod.printSignature(report.api))) {
                    dpermission = m.getValue();
                    break;
                }
            }
            //如果该api不存在于对应级别API的声明文档中，则不兼容受保护，或者不兼容没保护
            if(dpermission.isEmpty()) {
                SootMethod apiCaller = Scene.v().getMethod(apiMethod.printSignature(report.chain.get(report.chain.size() - 2)));
                SootMethod dApi = Scene.v().getMethod(apiMethod.printSignature(report.api));
                RvProtectedCallsite pa = compat.get(apiCaller);
                if(!pa.rv.contains(rv))
                {
                    //In API version {}: no such api, but protected", rv
                    types.put(rv,EvolutionFollowType.RvProtectedAPI);
                }
                else
                {
                    //"  In API version {}: no such api, protected", rv)
                    types.put(rv,EvolutionFollowType.NoRvProtectedAPI);
                }
                continue;
            }
            List<PCallChain> sc = new ArrayList<>();
            int flag=0;
            for(PCallChain it:report.syncCheck)
            {
                for(Permission p:it.Permissions)
                {
//                    if(dpermission.contains(p))
//                    {
//                        sc.add(it);
//                        break;
//                    }
                    for(Permission dp:dpermission)
                    {
                        if(Objects.equals(dp.toString(), p.toString()))
                        {
                            sc.add(it);
                            flag=1;
                            break;
                        }
                    }
                    if(flag==1)
                        break;
                }
            }
            List<PCallChain> sr = new ArrayList<>();
            flag=0;
            for(PCallChain it:report.syncRequest)
            {
                for(Permission p:it.Permissions)
                {
                    for(Permission dp:dpermission)
                    {
                        if(Objects.equals(dp.toString(), p.toString()))
                        {
                            sr.add(it);
                            flag=1;
                            break;
                        }
                    }
                    if(flag==1)
                        break;
                }
            }
            List<PCallChain> ac = new ArrayList<>();
            flag=0;
            for(PCallChain it:report.asyncCheck)
            {
                for(Permission p:it.Permissions)
                {
                    for(Permission dp:dpermission)
                    {
                        if(Objects.equals(dp.toString(), p.toString()))
                        {
                            ac.add(it);
                            flag=1;
                            break;
                        }
                    }
                    if(flag==1)
                        break;
                }
            }
            List<PCallChain> ar = new ArrayList<>();
            flag=0;
            for(PCallChain it:report.asyncRequest)
            {
                for(Permission p:it.Permissions)
                {
                    for(Permission dp:dpermission)
                    {
                        if(Objects.equals(dp.toString(), p.toString()))
                        {
                            ar.add(it);
                            flag=1;
                            break;
                        }
                    }
                    if(flag==1)
                        break;
                }
            }

            Pair<Boolean, Boolean> bo = new Pair<>(!sc.isEmpty()||!ac.isEmpty(), !sr.isEmpty()||!ar.isEmpty());
            if(!bo.getKey() && !bo.getValue())
                types.put(rv,EvolutionFollowType.NoCR);
            else if(bo.getKey() && !bo.getValue())
                types.put(rv,EvolutionFollowType.OnlyC);
            else if(!bo.getKey() && bo.getValue())
                types.put(rv,EvolutionFollowType.OnlyR);
            else
                types.put(rv,EvolutionFollowType.BothCR);
        }
        return types;
    }

    private static void dumpCompat(Path storePath, Map<SootMethod, RvProtectedCallsite> compat) throws IOException {
        Path folder = Paths.get("compatibility");

        List<String> sb = new ArrayList<>();
        sb.add(storePath.toString());
        sb.add("\n\n\n");
        for(Map.Entry<SootMethod, RvProtectedCallsite> map:compat.entrySet())
        {
            sb.add("In method: ");
            sb.add("    "+map.getKey().getSignature());
            Stmt callsite = map.getValue().stmt;
            List<Integer> rvs = map.getValue().rv;
            sb.add("   Callsite: ");
            if(callsite!=null)
                sb.add("    "+callsite.toString());
            else
                sb.add("null");
            sb.add("   Protected by: ");
            if(rvs!=null) {
                for (int i : rvs) {
                    sb.add(String.valueOf(i) + ",");
                }
            }
            sb.add("\n\n---\n\n");
        }
        Path thisPath = folder.resolve(storePath.getFileName());
        DoFiles.writeListTo(sb,thisPath.toString());
    }

    private static Map<SootMethod, RvProtectedCallsite> collectCompatibility(HBReport report) {
        // also make the assumption as previous return@outter
        LinkedHashMap<SootMethod,RvProtectedCallsite> compatMap = new LinkedHashMap<>();
        for(apiMethod m : report.chain)
        {
            SootMethod method = Scene.v().getMethod(apiMethod.printSignature(m));
            boolean returnflag = false;//用来return outter的
            for(Unit unit:method.getActiveBody().getUnits())
            {
                List<Integer> rv = new ArrayList<>();
                for(Tag t: unit.getTags())
                {
                    if(t instanceof RvAvailable)
                        rv.add(((RvAvailable) t).rv);
                }
                if(!rv.isEmpty()){
                    compatMap.put(method, new RvProtectedCallsite((Stmt)unit, rv));
                    returnflag=true;
                    break;
                }
            }
            if(returnflag==true)
                continue;
            compatMap.put(method,new RvProtectedCallsite(null, null));//(null,emptylist())
        }
        return compatMap;
    }

    private static void untagRvSentinal(HBReport report) {
        for(apiMethod m:report.chain)
        {
            SootMethod method = Scene.v().getMethod(apiMethod.printSignature(m));
            for(Unit unit: method.getActiveBody().getUnits())
            {
                List<Tag> rvs = new ArrayList<>();
                for(Tag t:unit.getTags())
                {
                    if(t instanceof RvAvailable)
                        rvs.add(t);
                }
                for(Tag t:rvs)
                {
                    unit.getTags().remove(t);
                }
            }
        }
    }

    private static void tagRvSentinal(HBReport report) throws InvalidObjectException {
        //System.out.println("==> TAGGING for chain "+report.storePath);
        List<apiMethod> callpath = report.chain;
        Set<Integer> rvRange = new HashSet<>();//预先设置rvRange：minSdkVersion——apkTargetVersion
        for(int i = targetMin;i<=targetMax;i++)
        {
            rvRange.add(i);
        }
        for(int i = 0;i<callpath.size()-1;i++)
        {
            SootMethod caller = Scene.v().getMethod(apiMethod.printSignature(callpath.get(i)));
            SootMethod callee = Scene.v().getMethod(apiMethod.printSignature(callpath.get(i+1)));
            RvReachabilitySolver rvSlvr = new RvReachabilitySolver(caller);
            for(Unit unit:caller.getActiveBody().getUnits())//遍历caller的units
            {
                if(isCallsiteOf(unit, callee)) {//找到调用callee的unit语句
                    Set<Integer> availableRvs = rvSlvr.solveAvailableRvs((Stmt)unit, rvRange);
                    StringBuilder rvStr = new StringBuilder();
                    for(int a:availableRvs)
                    {
                        rvStr.append(Integer.toString(a));
                        rvStr.append(",");
                    }
                    tagCallsiteByRvs(unit, availableRvs);
                    //callsite unit with rvs: [$rvStr]
                    Set<Integer> temp  = new HashSet<>();
                    for(int p:rvRange)
                    {
                        for(int q:availableRvs)
                        {
                            if(p==q)
                                temp.add(p);
                        }
                    }
                    rvRange = temp;
                    break;   // assume the method only call once
                }
            }
        }
    }

    private static void tagCallsiteByRvs(Unit unit, Set<Integer> rvs) {
        for(int it:rvs)
        {
            RvAvailable tag = RvAvailable.tag(it);
            unit.addTag(tag);
        }
    }

    private static boolean isCallsiteOf(Unit unit, SootMethod callee) {

        if(unit instanceof Stmt && ((Stmt) unit).containsInvokeExpr()) {
            InvokeExpr invokeExpr  = ((Stmt) unit).getInvokeExpr();
            return  invokeExpr.getMethod()== callee || invokeExpr.getMethodRef()==callee;
        }
        return false;
    }























}
