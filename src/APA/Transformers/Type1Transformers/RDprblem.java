package APA.Transformers.Type1Transformers;

import APA.Transformers.Config;
import heros.DefaultSeeds;
import heros.FlowFunction;
import heros.FlowFunctions;
import heros.InterproceduralCFG;
import heros.flowfunc.Identity;
import javafx.util.Pair;
import soot.*;
import soot.jimple.*;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.jimple.toolkits.ide.DefaultJimpleIFDSTabulationProblem;
import soot.jimple.toolkits.ide.icfg.JimpleBasedInterproceduralCFG;

import java.util.*;
/*
    N:Unit
    D:Pair<Value, Set<DefinitionStmt>>
    M:SootMethod
//I:InterproceduralCFG<Unit, SootMethod>
 */

public class RDprblem extends DefaultJimpleIFDSTabulationProblem<Pair<Value, Set<DefinitionStmt>>, InterproceduralCFG<Unit, SootMethod>>
{
    private final Unit entrypoint;
    private final Set<DefinitionStmt> globalSources = new ConcurrentHashSet<>();
    private final Map<SootField, Set<DefinitionStmt>> fieldFact;
//运用IFDS/IDE框架把所有问题定义成一个简单的到达定义的字符串数据流分析问题
    public RDprblem(JimpleBasedInterproceduralCFG icfg, Map<SootField, Set<DefinitionStmt>> fieldFact, Unit entrypoint, boolean intraP) {
        super(icfg);

        this.entrypoint = entrypoint;
        this.fieldFact = fieldFact;

    }
    @Override
    public Map<Unit, Set<Pair<Value, Set<DefinitionStmt>>>> initialSeeds() {
        return DefaultSeeds.make(Collections.singleton(entrypoint), this.zeroValue());
    }
    @Override
    protected Pair<Value, Set<DefinitionStmt>> createZeroValue() {
        Local zeroValue = Jimple.v().newLocal("<<zero>>", UnknownType.v());
        return new Pair<>(zeroValue, Collections.emptySet());
    }
    FlowFunction<Pair<Value, Set<DefinitionStmt>>> mFpKillAll= new FlowFunction<Pair<Value, Set<DefinitionStmt>>>() {
        @Override
        public Set<Pair<Value, Set<DefinitionStmt>>> computeTargets(Pair<Value, Set<DefinitionStmt>> source) {
            if(source.getKey() instanceof FieldRef)//如果source源节点的key包含字段引用
            {
                SootField field = ((FieldRef) source.getKey()).getField();
                if(!fieldFact.containsKey(field))//如果fieldFact中没有field
                    fieldFact.put(field,new ConcurrentHashSet<>());//开辟一个field对应的Map<SootField, Set<DefinitionStmt>>
                fieldFact.put(field,source.getValue());//fieldFact用于存放source对应语句的key-field和value
            }
            return Collections.emptySet();//如果没有字段引用，等于没说，empty
        }
    };
//方法流函数返回另一个对象，它实例化单个边的流函数，<N,D,M>
    @Override
    protected FlowFunctions<Unit, Pair<Value, Set<DefinitionStmt>>, SootMethod> createFlowFunctionsFactory()
    {
        return new FlowFunctions<Unit, Pair<Value, Set<DefinitionStmt>>, SootMethod>() {
            //四种流动边，单个流函数只是一个具有以下签名的函数对象<D>,对于每个源节点source，该函数返回流边连接到给定source的所有目标节点
            @Override
            public FlowFunction<Pair<Value, Set<DefinitionStmt>>> getNormalFlowFunction(Unit now, Unit pre)
            {
                if(now instanceof DefinitionStmt)
                {
                    Value leftOp = ((DefinitionStmt) now).getLeftOp();
                    Value rightOp = ((DefinitionStmt) now).getRightOp();
                    //如果leftOp不是字符串类型，那么它直接可以实例化？
                    if(!(leftOp.getType().toString().startsWith("java.lang.String")))//如果definitionStmt的左操作数!=String
                    {
                        return Identity.v();
                    }
                    else
                    {
                        if(leftOp instanceof ArrayRef)//如果左侧操作数为数组引用
                        {
                            Value arrBase = ((ArrayRef) leftOp).getBase();
                            //对于给定源节点source。四种流函数都返回流边连接到给定源的所有目标节点
                            return (source -> {
                                if (source != RDprblem.this.zeroValue())
                                {
                                    if (source.getKey().equivTo(arrBase) || source.getKey().equivTo(rightOp))
                                    {
                                        //    {r2} meets {r2[i1] = r1} -> merge r1 to r2
                                        // or {r3} meets {r2[i1] = r3} -> merge r3 to r2
                                        if(source.getValue().contains((DefinitionStmt) now))//如果该source的Definition语句集中已经包含now
                                            return Collections.singleton(source);//不做添加，直接返回
                                        else
                                        {
                                            Set<DefinitionStmt> newDefinitions = new HashSet<>(source.getValue());
                                            newDefinitions.add((DefinitionStmt) now);

                                            Pair<Value, Set<DefinitionStmt>> newFacts = new Pair<>(arrBase, newDefinitions);
                                            globalSources.addAll(newDefinitions);
                                            return Collections.singleton(newFacts);
                                        }

                                    }
                                    else
                                        return Collections.singleton(source);
                                }
                                else
                                    return Collections.singleton(source);
                            });
                        }
                        else//如果左侧操作数不为数组引用
                        {
                            Set<DefinitionStmt> n = (Collections.singleton(((DefinitionStmt) now)));
                            Pair<Value, Set<DefinitionStmt>> newFact = new Pair<>(leftOp, n);
                            return (source -> {
                                if (source != RDprblem.this.zeroValue())
                                {
                                    if (source.getKey().equivTo(leftOp))
                                        return Collections.emptySet();
                                    else if (source.getKey().equivTo(rightOp) || ((rightOp instanceof ArrayRef) && (source.getKey().equivTo(((ArrayRef) rightOp).getBase()))))
                                    {
                                        // {r1} meets {r2 = r1[i1]} -> 合并 r1 to r2
                                        // 请注意，获取 r1[i1] 不会杀死 r1

                                        if(source.getValue().contains((DefinitionStmt) now))//如果该source的Definition语句集中已经包含now
                                            return Collections.singleton(source);//不做添加，直接返回
                                        else
                                        {
                                            Set<DefinitionStmt> newDefinitions = new HashSet<>(source.getValue());
                                            newDefinitions.add((DefinitionStmt) now);

                                            Pair<Value, Set<DefinitionStmt>> newFacts = new Pair<>(leftOp, newDefinitions);
                                            globalSources.addAll(newDefinitions);
                                            return Collections.singleton(newFacts);
                                        }
                                    }
                                    else
                                    {
                                        return Collections.singleton(source);
                                    }

                                }
                                else
                                {
                                    globalSources.addAll(newFact.getValue());
                                    return Collections.singleton(newFact);
                                }
                            });
                        }
                    }
                }
                else
                    return Identity.v();
            }

            @Override
            public FlowFunction<Pair<Value, Set<DefinitionStmt>>> getCallFlowFunction(Unit callSite, SootMethod destinationMethod) {
                if(isBLACK(destinationMethod))//主要是记得存source源节点对应的fielFact来反应FP事实
                    return mFpKillAll;
                if(destinationMethod.getParameterCount()==0)
                    return mFpKillAll;
                InvokeExpr invokeExpr = ((Stmt)callSite).getInvokeExpr();

                //存常量事实constantFact
                Set<Pair<Value, Set<DefinitionStmt>>> constantFact = new ConcurrentHashSet<>();//返回一个空的新Set,返回的集合保留元素迭代顺序。
                int idx = 0;
                List<Value> argss = invokeExpr.getArgs();//存callSite中包含的形式参数
                //形式参数向实际参数传递？
                for (Value arg : argss)//遍历形式参数
                {
                    Type dest = destinationMethod.getParameterType(idx);//dest：实参的类型
                    EquivalentValue param = new EquivalentValue(Jimple.v().newParameterRef(dest, idx));//param：指定类型实参Ref
                    if(arg instanceof StringConstant && !Objects.equals(((StringConstant) arg).value, "Stub!" ))//如果形参是字符串常量&& ！="Stub！"
                    {
                        //形式参数向实际参数传递
                        Local tmpvar = Jimple.v().newLocal("$$p" + idx, arg.getType());//形式参数
                        AssignStmt assign = Jimple.v().newAssignStmt(tmpvar, arg);//形式参数传递语句tmpvar=arg
                        Pair<Value, Set<DefinitionStmt>> newFact = new Pair<>(param, Collections.singleton(assign));//实际参数+形式参数
                        constantFact.add(newFact);
                    }
                    idx++;
                }

                return (source -> {
                    Set<Pair<Value, Set<DefinitionStmt>>> nonConstantFact = new ConcurrentHashSet<>();
                    int idx1 = 0;
                    List<Value> argss1 = invokeExpr.getArgs();
                    //nonConstantFact
                    for (Value arg : argss1)
                    {
                        Type dest = destinationMethod.getParameterType(idx1);//dest：实参的类型
                        EquivalentValue param = new EquivalentValue(Jimple.v().newParameterRef(dest, idx1));//param：指定类型实参Ref
                        if((arg.equals(source.getKey())) && (arg.getType().toString().startsWith("java.lang.String"))) {//如果形参是字符串类型==source.key
                            // 处理传递参数，例如 foo($r1)
                            Pair<Value, Set<DefinitionStmt>> newFact = new Pair<>(param, source.getValue());
                            nonConstantFact.add(newFact);
                            break;//这里为什么要break
                        }
                        idx1++;
                    }
                    // 不变的事实不依赖于其他事实，都传播给被调用者
                    //gen=constantFact+nonConstantFact
                    Set<Pair<Value, Set<DefinitionStmt>>> gen = constantFact;
                    gen.addAll(nonConstantFact);

                    Set<DefinitionStmt> c = new ConcurrentHashSet<>();
                    for (Pair<Value, Set<DefinitionStmt>> valueSetPair : gen) {
                        c.addAll(valueSetPair.getValue());
                    }

                    globalSources.addAll(c);
                    return gen;

                });


            }

            @Override
            public FlowFunction<Pair<Value, Set<DefinitionStmt>>> getReturnFlowFunction(Unit callSite, SootMethod calleeMethod, Unit exitStmt, Unit returnSite) {

                return !(callSite instanceof DefinitionStmt) ? mFpKillAll : (exitStmt instanceof ReturnVoidStmt ? mFpKillAll : (!(exitStmt instanceof ReturnStmt) ? mFpKillAll : ((FlowFunction<Pair<Value, Set<DefinitionStmt>>>) source -> {
                    if ((((ReturnStmt)exitStmt).getOp().equivTo(source.getKey()))&&(((ReturnStmt)exitStmt).getOp().getType().toString().startsWith("java.lang.String")))
                    {
                            Pair<Value, Set<DefinitionStmt>> newFact = new Pair<>(((DefinitionStmt) callSite).getLeftOp(), source.getValue());
                            globalSources.addAll(source.getValue());
                            return Collections.singleton(newFact);

                    }

                    return Collections.emptySet();
                })));
            }

            @Override
            public FlowFunction<Pair<Value, Set<DefinitionStmt>>> getCallToReturnFlowFunction(Unit callSite, Unit returnSite) {
                if(!(callSite instanceof DefinitionStmt))
                {
                    return Identity.v();
                }
                else
                {
                    return (source -> ((DefinitionStmt)callSite).getLeftOp().equivTo(source.getKey()) ? Collections.emptySet() : Collections.singleton(source));
                }
            }


        };

    }

    public static boolean isBLACK(SootMethod destinationMethod) {
        for(int i = 0; i< Config.BLACK_LIST.size(); i++)
        {
            if(destinationMethod.getDeclaringClass().getName().startsWith(Config.BLACK_LIST.get(i)))
                return true;
        }
        return false;
    }
}
