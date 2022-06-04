package APA.Transformers.ManualOp;

import APA.Transformers.AnalysisSteps.CheckSite;
import APA.Transformers.AnalysisSteps.RequestSite;
import APA.Transformers.Config;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.DCallChain;
import APA.Transformers.apiRelate.PCallChain;
import APA.Transformers.apiRelate.api;
import APA.Transformers.apiRelate.apiMethod;
import org.apache.commons.io.FileUtils;
import soot.SootMethod;
import soot.jimple.toolkits.infoflow.CallChain;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DoFiles {
    public static void writeToFile(String s, String filePath) throws IOException {
        File file = Config.apkOutputDir.resolve(filePath).toFile();
        FileUtils.writeStringToFile(file,s,"UTF-8");
    }

    public static List<String> readLinesFrom(String filePath) throws IOException {
        File file = new File(filePath);
        return FileUtils.readLines(file,"UTF-8");
    }

    public static void writeListTo(List<String> list, String filename) throws IOException {
        Path realPath = Config.apkOutputDir.resolve(filename);
        File file = realPath.toFile();
        FileUtils.writeLines(file, "UTF-8", list, false);
    }

    public static void writeMethodMapTo(Map<apiMethod, Set<Permission>> map, String filePath) throws IOException {
        List<String> strings = new ArrayList<>();
        for (Map.Entry<apiMethod, Set<Permission>> dangerousApis : map.entrySet())
        {
            strings.add("Method:"+apiMethod.printApiMethod(dangerousApis.getKey()));
            for(Permission p: dangerousApis.getValue())
                strings.add(p.toString());
            strings.add("");
        }
        writeCollection(strings, filePath);

    }

    private static void writeCollection(List<String> strings, String filePath) throws IOException {
        Path realPath = Config.apkOutputDir.resolve(filePath);
        File file = realPath.toFile();
        FileUtils.writeLines(file, "UTF-8", strings, false);

    }

    public static void writeDangerousCallchainsTo(Set<DCallChain> dangerousCallchains, String filePath) throws IOException {
        List<String> strings = new ArrayList<>();
        for(DCallChain dangerousCallchain: dangerousCallchains)
        {
            strings.add("===========================================================");
            strings.add("DangerousApi:"+apiMethod.printApiMethod(DCallChain.getDangerousApis(dangerousCallchain)));
            for(apiMethod ap : dangerousCallchain.callChain)
            {
                strings.add("  "+apiMethod.printApiMethod(ap));
            }
            strings.add("");//换行
            strings.add("Need Permissions:");
            for(Permission permission:dangerousCallchain.permissions)
            {
                strings.add(permission.toString());
            }

        }
        writeCollection(strings, filePath);
    }

    public static void printReport(StepReport report) throws IOException {
        //输出路径
        String fileName = report.count+"-"+apiMethod.printApiMethod(report.api)+".txt";
        Path path = Paths.get("Reports", fileName);
        List<String> content = new ArrayList<>();
        content.add("ApiMethod : "+apiMethod.printApiMethod(report.api));
        content.add("DangerousApiCallChain : ");
        for(apiMethod a:report.chain)
        {
            content.add("  "+apiMethod.printApiMethod(a));
        }
        content.add("Permissions:");
        for(Permission p : api.apiToDangerousPermissions.get(report.api))
        {
            content.add("~~"+p.toString());
        }
        content.add("");
        content.add("");
        content.add("-------------------------------Declare Result--------------------------------");
        for(Map.Entry<Permission, Boolean> m1:report.declareRes.entrySet())
        {
            content.add(m1.getKey().toString()+"   "+m1.getValue());
        }
        content.add("-------------------------------Check Result--------------------------------");
        for(Map.Entry<Permission, List<CheckSite>> m2:report.checkRes.entrySet())
        {
            content.add(m2.getKey().toString()+"   ");
            for(CheckSite c:m2.getValue())
                content.add("  "+c.checker.getSignature());
        }
        content.add("-------------------------------Request Result--------------------------------");
        for(Map.Entry<Permission,List<RequestSite>> m3:report.requestRes.entrySet())
        {
            content.add(m3.getKey().toString()+"   ");
            for(RequestSite r:m3.getValue())
                content.add("  "+r.requester.getSignature());
        }
        content.add("-------------------------------Handle Result--------------------------------");
        for(Map.Entry<Permission, List<SootMethod>> m4:report.handleRes.entrySet())
        {
            content.add(m4.getKey().toString()+"   ");
            for(SootMethod sm:m4.getValue())
                content.add("  "+sm.getSignature());
        }

        DoFiles.writeListTo(content, path.toString());
        report.count++;
    }
}
