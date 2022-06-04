package APA.Transformers.AnalysisSteps;

import APA.Transformers.CFG;
import APA.Transformers.CG;
import APA.Transformers.Config;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.SootRelate.SootBodyUnitVisitor;
import APA.Transformers.Type1Transformers.RDprblem;
import APA.Transformers.Type1Transformers.SunnyTransformer;
import APA.Transformers.apiRelate.DCallChain;
import APA.Transformers.apiRelate.apiMethod;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.util.*;

public class Step3Request {
    public static Map<Permission, List<RequestSite>> findAllRequestsites(DCallChain chain) {
        Map<Permission, List<RequestSite>> requestBlock = new HashMap<>();
        for(Permission permission:chain.permissions)
        {
            List<RequestSite> requestSite = new ArrayList<>();
            Set<SootMethod> visited = new ConcurrentHashSet<>();
            int i=0;
            for(apiMethod method:chain.callChain)//forward
            {
                if(i!=chain.callChain.size()-1)
                {
                    SootMethod sootMethod = Scene.v().getMethod(apiMethod.printSignature(method));
                    SootMethod exceptMethod = Scene.v().getMethod(apiMethod.printSignature(chain.callChain.get(i+1)));
                    Set<UnindexRequestSite> set = new ConcurrentHashSet<>();
                    requestsites(new LinkedList<SootMethod>(Collections.singleton(sootMethod)), permission, exceptMethod, visited, set, 10);
//                    if(set.size() ==0)
//                        System.out.println("niuniuniu");
                    for(UnindexRequestSite cs:set)
                    {
                        requestSite.add(new RequestSite(i,cs.requester,cs.unit,cs.invoke));
                    }
                    i++;
                }
                else
                    break;;
            }
            requestBlock.put(permission,requestSite);
        }
        return requestBlock;
    }

    private static void requestsites(LinkedList<SootMethod> stack, Permission permission, SootMethod except, Set<SootMethod> visited, Set<UnindexRequestSite> sites, int level) {
        if(level == 0) // level including method itself
            return;
        //在stack方法内部进行检查是否有REQUEST_API的调用+REQUEST_API调用的是不是permission
        requestsitesInMethod(stack, permission, sites);
        SootMethod method = stack.get(stack.size()-1);
        visited.add(method);
        Iterator<SootMethod> itSm = CG.getCISCallFrom(method);//找到method后面的所有son
        Set<SootMethod> ne = new ConcurrentHashSet<>();
        while(itSm.hasNext())
        {
            SootMethod sm = itSm.next();
            if(!Objects.equals(sm.getSignature(), except.getSignature()))
                ne.add(sm);
        }
        Iterator<SootMethod> newitSm = ne.iterator();
        while(newitSm.hasNext())
        {
            SootMethod child = newitSm.next();
            if(visited.contains(child))
                return;
            if(RDprblem.isBLACK(child))
                return;
            stack.addLast(child);
            requestsites(stack, permission, except, visited, sites, level-1);
            stack.removeLast();
        }
    }

    private static void requestsitesInMethod(LinkedList<SootMethod> stack, Permission permission, Set<UnindexRequestSite> sites) {
        //检查stack中末尾的那个SootMethod方法内部是否有request
        CFG.visitAllStmts(stack.get(stack.size() - 1), new SootBodyUnitVisitor() {
            @Override
            public void visitInvoke(InvokeExpr invoke, Unit unit) {
                //找到stack末尾SootMethod方法体中stmt语句invoke的另一个方法
                String sootSig = invoke.getMethod().getSignature();
                //如果该unit调用的api就是request_API
                //System.out.println(sootSig);
                if(Config.REQUEST_APIS.contains(sootSig))
                {
                    //找到到达unit语句的permissions
                    Set<Permission> saPermission = SunnyTransformer.concretePermissionValuesAt(unit);
                    int flag=0;//用于标记permission是否在该unit所检查的saPermission中
                    for(Permission p:saPermission)
                    {
                        if(Objects.equals(p.toString(), permission.toString()))
                        {
                            flag=1;
                            break;
                        }
                    }
                    if(flag==1)
                    {
                        //如果permission在该unit所检查的saPermission中，如果在，创建UnindexRequestSite
                        SootMethod requester = (stack.size()==1)?Scene.v().getMethod(sootSig):stack.get(1);//？？为啥是stack.get(1)
                        UnindexRequestSite triple = new UnindexRequestSite(requester, unit, invoke);
                        sites.add(triple);
                    }
                }
            }
        });
    }
}
