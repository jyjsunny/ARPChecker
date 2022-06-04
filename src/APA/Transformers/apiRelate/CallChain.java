package APA.Transformers.apiRelate;

import APA.Transformers.*;
import APA.Transformers.ManualOp.Visitor;

import APA.Transformers.PermissionRelate.Permission;

import soot.Scene;
import soot.SootClass;
import soot.SootMethod;

import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.toolkits.graph.ExceptionalUnitGraph;
import soot.util.Chain;

import java.util.*;


public class CallChain {
    public static Set<DCallChain> dangerousCallChains= new HashSet<>();

    public static Set<DCallChain> getDangerousCallchains() {
        if(!dangerousCallChains.isEmpty())
            return dangerousCallChains;
        if(api.apiToDangerousPermissions.isEmpty())
            throw new RuntimeException("No dangerous methods found");
        //遍历apk中含有的所有dangerous api
        for(apiMethod a : api.apiToDangerousPermissions.keySet())
        {
            LinkedList<apiMethod> callChain = new LinkedList<>();
            //callChain头部插入当前dangerous的apiMethod a；
            callChain.addFirst(a);

            travelCallGraph(callChain, new ConcurrentHashSet<>(), new Visitor() {
                @Override
                public void happly(LinkedList<apiMethod> chain) {
                    Visitor.super.happly(chain);
                    List<apiMethod> cun = new ArrayList<>();
                    for (apiMethod a:callChain)
                    {
                        cun.add(a);
                    }
                    Set<Permission> permissions = api.apiToDangerousPermissions.get(cun.get(cun.size()-1));//用不用-1，用
                    DCallChain dc = new DCallChain(cun, permissions);
                    dangerousCallChains.add(dc);//DCallChain需要定义一下
                }
            });
        }

        return dangerousCallChains;//用于存放每个dangerous api的callChain和它们所需permissions的对应关系

    }

    public static void travelCallGraph(LinkedList<apiMethod> chain, Set<apiMethod> visited, Visitor visitor ) {
        if(terminateAtSelf(chain))
        {
          visitor.happly(chain);
          return;
        }
        apiMethod method = chain.getFirst();//method是chain头部的元素
        visited.add(method);//把method加入到已经访问过的visited中
        //加载api的definingClass
        SootClass clazz = Scene.v().loadClass(method.definingClass.name, SootClass.BODIES);
        SootMethod st = null;

        try {
            //st:通过method的subSignature得到的sootMethod
            st = clazz.getMethod(apiMethod.printSubsignature(method));
        } catch (Exception e) {
            return;
        }
        Iterator<SootMethod> smIt = CG.getCallTo(st);//smIt用于找st的所有爸爸？
        //遍历sootMethod的parent

        while(smIt.hasNext())
        {
            SootMethod nextMethod = smIt.next();
            apiMethod babaApi = apiMethod.fromSootSignature(nextMethod.getSignature());
            boolean flag = false;
            for(apiMethod a:visited)
            {
                if(apiMethod.printApiMethod(a).equals(apiMethod.printApiMethod(babaApi)))
                {
                    flag=true;
                    break;
                }
            }
            if(ReachBLACKApi(babaApi) && chain.size()==1)//如果chain是Black或者chain只包含自己，没有爸爸
            {
                System.out.println("");//不再访问
            }
            else if(ReachBLACKApi(babaApi) || ReachDummy(babaApi))//如果到达出口点或者blackapi，统一visitor
            {
                visitor.happly(chain);
            }
            else if(!flag)//!visited.contains(babaApi)
            {
                chain.addFirst(babaApi);//把babaApi加进去
                travelCallGraph(chain, visited,visitor);
                chain.removeFirst();
            }

        }
    }

    private static void happly(LinkedList<apiMethod> chain) {


        Set<Permission> permissions = api.apiToDangerousPermissions.get(chain.get(chain.size()-1));//用不用-1，用

        DCallChain dc = new DCallChain(chain, permissions);

        dangerousCallChains.add(dc);//DCallChain需要定义一下
    }


    private static boolean ReachDummy(apiMethod babaApi) {
        String clazz = babaApi.definingClass.name;
        String method = babaApi.methodName;
        return (Objects.equals(clazz, "dummyMainClass")) || (Objects.equals(clazz, "java.lang.Thread") && Objects.equals(method, "start"));
    }

    private static boolean ReachBLACKApi(apiMethod apiM) {
        for(int i = 0; i< APA.Transformers.Config.BLACK_LIST.size(); i++)
        {
            if(apiM.definingClass.name.startsWith(Config.BLACK_LIST.get(i)))
                return true;
        }
        return false;
    }


    public static Set<DCallChain> removeWithTrycatch(Set<DCallChain> dangerousCallchains) {
        Set<DCallChain> noTCdangerousCallchains = new ConcurrentHashSet<>();
        for(DCallChain dc: dangerousCallchains)
        {
            if(!hasTryCatch(dc))
                noTCdangerousCallchains.add(dc);
        }
        return noTCdangerousCallchains;
    }

    private static boolean hasTryCatch(DCallChain dc) {

        for(int i=0;i<dc.callChain.size()-1;i++)
        {
            apiMethod caller = dc.callChain.get(i);//调用者
            apiMethod callee = dc.callChain.get(i+1);//被调用者
            SootMethod callerSootMethod = Scene.v().getMethod(apiMethod.printSignature(caller));

            SootMethod calleeSootMethod = Scene.v().getMethod(apiMethod.printSignature(callee));
            ExceptionalUnitGraph cfg = new ExceptionalUnitGraph(callerSootMethod.getActiveBody());

            Iterator<Tri> cubs= CFG.findAllCallsites(callerSootMethod);//找到caller方法体中所有callsites
            if(cubs==null)
                return false;
            while(cubs.hasNext())
            {
                Tri cub=cubs.next();

                if((cub.invoke.getMethod().getSignature()==calleeSootMethod.getSignature()) || (cub.invoke.getMethodRef().getSignature()==calleeSootMethod.getSignature()))
                {

                    if(! cfg.getExceptionalSuccsOf(cub.unit).isEmpty())
                        return true;
                }
            }

        }
        return false;

    }

    private static boolean terminateAtSelf(List<apiMethod> chain) {
        if(chain.size()>1)
        {
            if(selfReachThreshold(chain))
                return true;
            if(selfReachUncaughtException(chain))
                return true;
            if(selfReachLambdaRunnable(chain))//有问题
                return true;
            if(selfReachRunnable(chain))
                return true;
            if(selfReachCallable(chain))
                return true;
        }
        return false;

    }

    private static boolean selfReachCallable(List<apiMethod> chain) {
        return SAMReacher(chain,"java.lang.Runnable", "run");
    }

    private static boolean selfReachRunnable(List<apiMethod> chain) {
        return SAMReacher(chain,"java.util.concurrent.Callable", "call");
    }
    private static boolean SAMReacher(List<apiMethod> chain,String className,String method)
    {
        if (!Objects.equals(chain.get(0).methodName, method))
        {
            return false;
        }
        String selfClazz = chain.get(0).definingClass.name;
        SootClass clazz = Scene.v().loadClass(selfClazz, SootClass.HIERARCHY);
        return isSubclass(clazz,className);
    }

    private static boolean isSubclass(SootClass clazz,String className) {
        if(clazz == null)
            return false;
        for(SootClass sc:clazz.getInterfaces())
        {
            if(Objects.equals(sc.getName(), className))
                return true;
        }
        String cn = clazz.getName();
        if(cn==null)
            cn="";
        if(cn.equals("java.lang.Object"))
            return false;    // no further subclasses
        return isSubclass(clazz.getSuperclass(),className);
    }

    private static boolean selfReachLambdaRunnable(List<apiMethod> chain) {
        String clz = chain.get(0).definingClass.shortName;
        String mtd = chain.get(0).methodName;
        if(clz!=null&&mtd!=null)
        {
            if(clz.startsWith("-$$Lambda$")&& mtd.equals("run"))
                return true;
            else
                return false;
        }
        else
            return false;

    }

    private static boolean selfReachUncaughtException(List<apiMethod> chain) {
        if(!Objects.equals(chain.get(0).methodName, "uncaughtException"))//这个一般都是没有else
            return false;
        String selfClazz = chain.get(0).definingClass.name;
        Chain<SootClass> interfaces = Scene.v().loadClass(selfClazz, SootClass.HIERARCHY).getInterfaces();
        for(SootClass c:interfaces)
        {
            if(Objects.equals(c.getName(), "java.lang.Thread$UncaughtExceptionHandler"));
            {
                return true;
            }
        }
        return false;
    }

    private static boolean selfReachThreshold(List<apiMethod> chain) {
        return chain.size() >= 10;
    }
}
