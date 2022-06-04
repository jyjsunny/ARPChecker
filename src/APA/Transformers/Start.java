package APA.Transformers;


import APA.Transformers.AnalysisSteps.*;

import APA.Transformers.ManualOp.DoFiles;
import APA.Transformers.ManualOp.RevStepReport;
import APA.Transformers.ManualOp.StepReport;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.Type1Transformers.BillTransformer;
import APA.Transformers.Type1Transformers.SunnyTransformer;
import APA.Transformers.apiRelate.*;
import javafx.util.Pair;
import soot.PackManager;
import soot.Scene;
import soot.Transform;
import soot.options.Options;

import java.nio.file.Paths;
import java.util.*;


public class Start {
    public static String apkPath="/Users/jiangjiayi/android/APER-ARPfix-benchmark-master/Type-1/Ventivader_Buggy.apk";
    public static String androidSdkJarPath="/Users/jiangjiayi/android/APER/android-platforms";
    public static String mappingPath="/Users/jiangjiayi/android/APER/APER-mapping";

    //--exclude-libs在后面有定义
    //-with-exdir、without obfscan、filter trycatch


    public static void main(String[] args) throws Throwable {
        Config.init();//通过APK Parser得到一些apk的文件信息
        DoFiles.writeToFile("apk's Target Version:"+Config.apkTargetVersion,"apkTargetVersion.txt");
        DoFiles.writeToFile("Package id:"+Config.apkPackageName,"apkPackageName.txt");
        //（1）用flowdroid生成callgraph
        CG.generate();
        setupSoot(args);//为数据流分析Package配置Soot
        Scene.v().loadNecessaryClasses();
        //（2）预定义字符串到达定义的数据流分析+onRequestPermissionResult分析
        PackManager.v().getPack("wjap").add(new Transform("wjap.SunnyTrans", new SunnyTransformer()));
        PackManager.v().getPack("jap").add(new Transform("jap.BillTrans", new BillTransformer()));
        PackManager.v().runPacks();//这步骤必须有，不然进不去Transformer的internalTransformer
//type1
        //（一）获取指定apk的危险API调用链
        //得到对应API等级的APER-mapping【/Users/jiangjiayi/android/APER/APER-mapping/API28】
        Mapping mapping = Mapping.get("aper", Paths.get(mappingPath),Config.apkTargetVersion);
        //遍历该API等级下的-mapping.txt，并将permission与method拆分，并存入Map<Permission, Set<apiMethod>>中
        Map<Permission, Set<apiMethod>> allPermissionToMethods = mapping.mapPermissionToMethods();


        //得到对应apk中，属于指定API的permission组中permission的数量，并标出属于DANGEROUS的permission（APKMeta解析Manifest得到apk内所有permission）
        Step1Declare.saveDeclaredPermissions("declaredPermissions.txt");//用于存储apk中声明的（permissions+dangerous permissions）
        //提取apk中的所有危险API调用，并从allPermissionToMethods中寻找危险API所需要的permissions
        Map<apiMethod, Set<Permission>> dangerousApis = api.getDangerousApis(allPermissionToMethods);//得到所有需要危险permission的api以及permission映射
        //写入dangerousApis.txt
        DoFiles.writeMethodMapTo(dangerousApis, "dangerousApis.txt");


        //通过遍历apiToDangerousPermissions，+控制流分析CG得到危险api调用链，写的太繁琐了，可以简化
        Set<DCallChain> dangerousCallChains= CallChain.getDangerousCallchains();//更新dangerousCallChains
        System.out.println("Extracted "+dangerousCallChains.size()+" dangerous api-call-chains");
        DoFiles.writeDangerousCallchainsTo(dangerousCallChains,"dangerousApisCallChains.txt");


        //返回不包含trycatch的危险api调用chain
        Set<DCallChain> noTryCatchDangerousCallChains  = CallChain.removeWithTrycatch(dangerousCallChains);
        System.out.println("filtedDangerousApisCallChains:"+noTryCatchDangerousCallChains.size());
        DoFiles.writeDangerousCallchainsTo(noTryCatchDangerousCallChains,"filtedDangerousApisCallChains.txt");

        //（二）根据CHECK—API和REQUEST_API获取输出checkchain和requestchain（IFDS+数据流）
        RevStepReport revreport = RevStepReport.reverseAnalyze();

//        //（三）查找所有危险的调用链，并进行步骤检查
        Set<StepReport> reports = guideAnalyze.analyze(noTryCatchDangerousCallChains);

//type2:
        //（四）基于reports进行同步分析
        Map<String,Set<BestPracticeFollowType>> sync = SynchronousAnalyzer.synchronousAnalyze(reports);

        //（五）基于revreports进行异步分析
        Map<String,Set<Pair<HappenBeforeFollowType,Set<PCallChain>>>> async = AsynchronousAnalyzer.asynchronousAnalyze(reports, revreport);

        //（六）合并同步+异步检查结果
        List<HBReport> hbreports = HBReport.aggregate(reports, revreport, sync, async);

        //（七）分析 os-evolution 兼容性
        OSEvolutionAnalyzer.analyzeCompatibility(hbreports);
    }

    private static void setupSoot(String[] args) {
        //Options.v().set_exclude(Config.excludedPkgs);
        //Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_whole_program(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_force_android_jar(Config.versionSdkFile.toString());
        Options.v().set_soot_classpath(Config.versionSdkFile.toString());
        Options.v().set_process_dir(Collections.singletonList(Config.apkPath));
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_validate(false);
        Options.v().set_verbose(true);
        Options.v().set_debug(true);
    }





}


