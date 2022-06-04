package APA.Transformers.AnalysisSteps;

import APA.Transformers.MCG.*;
import APA.Transformers.Manifest;
import APA.Transformers.ManualOp.SigParseResult;
import APA.Transformers.ManualOp.SignatureUtil;
import APA.Transformers.apiRelate.CallChain;
import APA.Transformers.apiRelate.apiClass;
import com.sun.codemodel.internal.JClass;
import com.sun.deploy.config.Config;
import javafx.util.Pair;
import jdk.nashorn.internal.IntDeque;
import org.dom4j.DocumentException;
import soot.*;
import soot.jimple.AbstractStmtSwitch;
import soot.jimple.InvokeStmt;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import sun.awt.HKSCS;

import java.util.*;

public class ModuleCGAnalyzer {
    public static Manifest manifest;//通过parseManifest得到apk中的所有manifest信息
    private static final ArrayDeque<CallerMethod> methodStack = new ArrayDeque<>();
    static {
        try {
            manifest = Manifest.parse(new Manifest(ManifestAnalyzer.manifestText));
        } catch (DocumentException e) {
            e.printStackTrace();
        }
    }

    public static Set<String> cmpNames  = getNames(manifest) ;//cmpNames: 所有模块内的组件名称(包含manifest中的全部activity、service、receiver）

    private static Set<String> getNames(Manifest manifest) {
        Set<String> maniName = new HashSet<>();
        for(Activity a:manifest.activity) {
            maniName.add(a.name);
        }
        for(Service s:manifest.service)
        {
            maniName.add(s.name);
        }
        for(Receiver r:manifest.receiver)
        {
            maniName.add(r.name);
        }
        return maniName;
    }

    public static Map<apiClass, Set<apiClass>> getModuleCG() {
        Set<Edge> wholeEdge= new HashSet<>();
        for (SootClass sootClass: Scene.v().getClasses()) {
            if(!isComponent(sootClass.getName()))
                continue;
            List<SootMethod> sootMethods = sootClass.getMethods();//获取该组件类中的所有方法
            for (SootMethod sootMethod: sootMethods) {
                /* 查找所有回调函数作为每个组件的入口点 */
                wholeEdge.addAll(funcAnalyzeRecursive(sootMethod, sootClass.getName(), 3));
            }
        }
        System.out.println( "Total: ${wholeEdge.size} edges in module call graph");

//        GraphConstructor graphConstructor = GraphConstructor(this.manifest, wholeEdge)
//        val dotPath = Config.get().apkOutputDir.resolve("mcg.dot")
//        graphConstructor.drawGarph(dotPath.toString())
//        LogUtil.info(this, "Draw mcg to dot")

        //return adapt(graphConstructor.edges);
        return new HashMap<>();
    }
    private static Map<apiClass,Set<apiClass>> adapt(Set<Pair<String,String>> graph)
    {
        Map<apiClass,Set<apiClass>> newGraph = new HashMap<>();
        for(Pair<String,String> p:graph)
        {
            apiClass innode = new apiClass(p.getKey());
            apiClass outnode = new apiClass(p.getValue());
            if(!newGraph.containsKey(innode))
                newGraph.put(innode,new HashSet<>());
            newGraph.get(innode).add(outnode);
        }
        return newGraph;
    }
    private static Set<Edge> funcAnalyzeRecursive(SootMethod sootMethod, String rootClassName, int depth) {
        LinkedHashSet<Edge> edges= funcAnalysis(sootMethod, rootClassName);//在单个函数中分析调用点
        if (depth > 0) {
            CallGraph cg = Scene.v().getCallGraph();//得到方法间的调用图
            Iterator<Edge> it = cg.edgesOutOf(sootMethod);//得到从该方法中出来的后续边
            while (it.hasNext()) {
                Edge next = it.next();
                if (next.isClinit()|| next.kind() == Kind.FINALIZE || !next.srcStmt().containsInvokeExpr()) {
                    continue;
                }
                methodStack.push(new CallerMethod(next.srcUnit(), sootMethod));//methodStack：存储caller方法的调用语句
                edges.addAll(funcAnalyzeRecursive((SootMethod)next.getTgt(), rootClassName, depth - 1));
                methodStack.poll();
            }
        }
        return edges;//edges=在sootmethod的每个单个函数中的调用点+sootMethod的往下三代method
    }

    private static LinkedHashSet<Edge> funcAnalysis(SootMethod sootMethod, String rootClassName) {
        LinkedHashSet<Edge> edges= new LinkedHashSet<>();
        if (!sootMethod.isConcrete())//？？如果sootMethod不是Concrete的
            return edges;
        Body body = sootMethod.retrieveActiveBody();
        /* 在方法主体中移动单元以识别每个调用点 */
        for(Unit unit : body.getUnits())
        {
            unit.apply(new AbstractStmtSwitch() {
                @Override
                public void caseInvokeStmt(InvokeStmt stmt) {
                    //识别上下文注册的receivers
                    SigParseResult checkResult = SignatureUtil.parseIntentArg(stmt);
                    if(checkResult != null) {
                        if (checkResult.isBCReceiver) {
                            IntentFilter intentFilter = new IntentFilter(checkResult.identifier, methodStack);
                            //intentFilter.backwardSlice(sootMethod, unit);

                            if (intentFilter.findDef) {
                                //"Find broadcast receiver at ${sootMethod.declaringClass}"
                                //ModuleCGAnalyzer.createReceiver(rootClassName, intentFilter);
                            }
                        }
                    }

//                    /* Identify Intents */
//                    if (!checkResult.isBCReceiver) {
//                        //LogUtil.debug(this, "Find ${checkResult.apiName} in ${sootMethod.name}")
//                        val intent = Intent(checkResult.identifier, methodStack).also { itt ->
//                                itt.backwardSlice(sootMethod, it)
//                        }
//                        if (intent.findDef) {
//                            LogUtil.debug(this, "Intent resolve successfully!")
//                            edges.add(Edge(rootClassName, checkResult.apiName, intent, null))
//                        } else
//                            LogUtil.debug(this, "Intent resolve failed!")
//                    }
                }
            });
        }

        return edges;
    }
    private void addReceiver(Receiver receiver)
    {
        manifest.addReceiver(receiver);
    }

    private void addCmp(String cmpName){
        cmpNames.add(cmpName);
    }

//    private static void createReceiver(String className, IntentFilter intentFilter) {
//        this.addReceiver((new Receiver(className, Collections.singletonList(intentFilter))));
//        this.addCmp(className);
//    }

    private static boolean isComponent(String name) {
        if(name.contains("$"))
            return cmpNames.contains(name.substring(0,name.indexOf("$")));
        else
            return cmpNames.contains(name);
    }



















}
