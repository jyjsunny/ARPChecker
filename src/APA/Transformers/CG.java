package APA.Transformers;


import APA.Transformers.SootRelate.SootConfig;
import heros.solver.Pair;
import soot.MethodOrMethodContext;
import soot.Scene;
import soot.SootMethod;
import soot.jimple.infoflow.InfoflowConfiguration;
import soot.jimple.infoflow.android.SetupApplication;
import soot.jimple.infoflow.android.config.SootConfigForAndroid;
import soot.jimple.infoflow.collect.ConcurrentHashSet;
import soot.jimple.infoflow.config.IInfoflowConfig;
import soot.jimple.toolkits.callgraph.CallGraph;
import soot.jimple.toolkits.callgraph.Edge;
import soot.jimple.toolkits.callgraph.Sources;
import soot.jimple.toolkits.callgraph.Targets;
import soot.options.Options;

import java.util.*;
import java.util.function.Consumer;

import static java.lang.Thread.yield;

public  class CG {
    public static CallGraph callGraph;
    public static void generate()
    {
        //开始infoflow分析apk
        SetupApplication infoflowApplication =  new SetupApplication(Config.versionSdkFile.toString(),Config.apkPath);
        //IInfoflowConfig sootConfigForAndroid;

        IInfoflowConfig sootConfigForAndroid = new SootConfigForAndroid(){
            public void setSootOptions(Options options, InfoflowConfiguration config)
            {
                super.setSootOptions(options, config);//?
                config.setCallgraphAlgorithm(InfoflowConfiguration.CallgraphAlgorithm.CHA);//采用flowdroid中算法CHA
                //以下部分等同于：Scene.v().init()
                Scene scene = Scene.v();
                SootConfig.setupSoot(scene);

            }

        };
        infoflowApplication.setSootConfig(sootConfigForAndroid);
        infoflowApplication.setCallbackFile(Config.androidCallbacksFile.toString());
        infoflowApplication.constructCallgraph();

        callGraph = Scene.v().getCallGraph();
    }


    public static Iterator<Pair<SootMethod, SootMethod>> getAllEdges() {
        //这里注意不能用set
        List<Pair<SootMethod, SootMethod>> edgeSet = new ArrayList<>();
        for(Edge edge : callGraph)
        {
            SootMethod head = edge.src().method();
            SootMethod tail = edge.tgt().method();
            edgeSet.add(new Pair<>(head, tail));
        }
        return edgeSet.iterator();
    }
    public static Iterator<SootMethod> getCallTo(SootMethod method) {
        Sources parents = new Sources(callGraph.edgesInto(method));//根据流入method的边得到source
        return new Iterator<SootMethod>() {
            @Override
            public boolean hasNext() {
                return parents.hasNext();
            }

            @Override
            public SootMethod next() {
                return parents.next().method();
            }
        };

    }

    public static Iterator<SootMethod> getCISCallFrom(SootMethod method) {
        Set<SootMethod> met = new ConcurrentHashSet<>();
        Targets children = new Targets(CG.callGraph.edgesOutOf(method));
        //打印出从method出来的所有edges，它们的爸爸都是method
        while(children.hasNext())
        {
            MethodOrMethodContext it = children.next();
            //这里注意
            met.add(it.method());
        }
        return met.iterator();

    }
}
