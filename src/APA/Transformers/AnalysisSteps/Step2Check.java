package APA.Transformers.AnalysisSteps;

import APA.Transformers.*;
import APA.Transformers.ManualOp.Visitor;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.SootRelate.SootBodyUnitVisitor;
import APA.Transformers.Type1Transformers.RDprblem;
import APA.Transformers.Type1Transformers.SunnyTransformer;
import APA.Transformers.apiRelate.DCallChain;
import APA.Transformers.apiRelate.PCallChain;
import APA.Transformers.apiRelate.apiMethod;
import soot.Scene;
import soot.SootMethod;
import soot.Unit;
import soot.jimple.InvokeExpr;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.util.*;

public class Step2Check {
    public static Set<PCallChain> getCheckCallchains() {
        Set<PCallChain> checkChains= new ConcurrentHashSet<>();
        for(String checkApi: Config.CHECK_APIS)
        {
            apiMethod method = apiMethod.fromSootSignature(checkApi);
            //收集所有checkApi对应的checkChain
            LinkedList<apiMethod> checkChain = apiMethod.collectCallchainsTo(method, new Visitor() {
                @Override
                public void happly(LinkedList<apiMethod> chain) {
                    Visitor.super.happly(chain);
                    String chk = apiMethod.printSignature(chain.get(chain.size() - 1));//check_API
                    SootMethod checker = Scene.v().getMethod(apiMethod.printSignature(chain.get(chain.size() - 2)));//含有check_API调用的方法
                    //控制流分析checker方法体中的所有stmt
                    CFG.visitAllStmts(checker, new SootBodyUnitVisitor() {
                        @Override
                        public void visitInvoke(InvokeExpr invoke, Unit unit) {
                            SootBodyUnitVisitor.super.visitInvoke(invoke, unit);
                            if (Objects.equals(invoke.getMethod().getSignature(), chk)) {
                                Set<Permission> saPermission = SunnyTransformer.concretePermissionValuesAt(unit);
                                List<apiMethod> cun = new ArrayList<>();
                                for (apiMethod a:chain)
                                {
                                    cun.add(a);
                                }
                                checkChains.add(new PCallChain(cun, saPermission));
                            }
                        }
                    });
                }
            });

        }
        return checkChains;
    }

    public static Set<PCallChain> getRequestCallchains() {
        Set<PCallChain> requestChains= new ConcurrentHashSet<>();
        for(String requestApi: Config.REQUEST_APIS)
        {
            apiMethod method = apiMethod.fromSootSignature(requestApi);
            //收集所有checkApi对应的checkChain
            LinkedList<apiMethod> requestChain = apiMethod.collectCallchainsTo(method, new Visitor() {
                @Override
                public void happly(LinkedList<apiMethod> chain) {
                    Visitor.super.happly(chain);
                    String req = apiMethod.printSignature(chain.get(chain.size() - 1));//request_API
                    SootMethod requester = Scene.v().getMethod(apiMethod.printSignature(chain.get(chain.size() - 2)));//含有check_API调用的方法
                    //控制流分析checker方法体中的所有stmt
                    CFG.visitAllStmts(requester, new SootBodyUnitVisitor() {
                        @Override
                        public void visitInvoke(InvokeExpr invoke, Unit unit) {
                            SootBodyUnitVisitor.super.visitInvoke(invoke, unit);
                            if (Objects.equals(invoke.getMethod().getSignature(), req)) {
                                List<apiMethod> cun = new ArrayList<>();
                                for (apiMethod a:chain)
                                {
                                    cun.add(a);
                                }
                                Set<Permission> saPermission = SunnyTransformer.concretePermissionValuesAt(unit);
                                requestChains.add(new PCallChain(cun, saPermission));
                            }
                        }
                    });

                }
            });

        }
        return requestChains;
    }

    public static Map<Permission, List<CheckSite>> findAllChecksites(DCallChain chain) {
        Map<Permission, List<CheckSite>> checkBlock = new HashMap<>();
        for(Permission permission:chain.permissions)
        {
            List<CheckSite> checkSite = new ArrayList<>();
            Set<SootMethod> visited = new HashSet<>();
            int i=0;
            for(apiMethod method:chain.callChain)//forward
            {
                if(i!=chain.callChain.size()-1)
                {
                    SootMethod sootMethod = Scene.v().getMethod(apiMethod.printSignature(method));
                    SootMethod exceptMethod = Scene.v().getMethod(apiMethod.printSignature(chain.callChain.get(i+1)));
                    Set<UnindexCheckSite> set = new ConcurrentHashSet<>();
                    checksites(new LinkedList<>(Collections.singleton(sootMethod)), permission, exceptMethod, visited, set, 10);
//这里i代表是callChain中的第几个apiMethod：0，1，2，3
                    for(UnindexCheckSite cs:set)
                    {
                        checkSite.add(new CheckSite(i,cs.checker,cs.unit,cs.invoke));
                    }
                }
                else
                    break;
                i++;
            }
            checkBlock.put(permission,checkSite);
        }
        return checkBlock;
    }
    // recursive call to expand trace
    private static void checksites(LinkedList<SootMethod> stack,//第一次call只有一个sootMethod
                                   Permission permission,//需要check的permission
                                   SootMethod except,//exceptMethod
                                   Set<SootMethod> visited,
                                   Set<UnindexCheckSite> sites,
                                   int level) {
        if(level == 0) // level including method itself
            return;
        //在stack方法内部进行检查是否有Check_API的调用+Check_API调用的是不是permission
        checksitesInMethod(stack, permission, sites);
        SootMethod method = stack.get(stack.size()-1);//stack.last
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

            if (!visited.contains(child) && !RDprblem.isBLACK(child)) {
                stack.addLast(child);
                checksites(stack, permission, except, visited, sites, level - 1);
                stack.removeLast();
            }
        }

    }

    private static void checksitesInMethod(LinkedList<SootMethod> stack, Permission permission, Set<UnindexCheckSite> sites) {
        //检查stack中末尾的那个SootMethod方法内部是否有check
        CFG.visitAllStmts(stack.get(stack.size() - 1), new SootBodyUnitVisitor() {
            @Override
            public void visitInvoke(InvokeExpr invoke, Unit unit) {
                //找到stack末尾SootMethod方法体中stmt语句invoke的另一个方法
                String sootSig = invoke.getMethod().getSignature();
                //如果该unit调用的api就是CHECK_API
                //System.out.println(sootSig);
                if(Config.CHECK_APIS.contains(sootSig))
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
                        //如果permission在该unit所检查的saPermission中，如果在，创建UnindexCheckSite
                        SootMethod checker = (stack.size()==1)?Scene.v().getMethod(sootSig):stack.get(1);//？？为啥是stack.get(1)
                        UnindexCheckSite triple = new UnindexCheckSite(checker, unit, invoke);
                        sites.add(triple);
                    }
                }
            }
        });
    }
}
