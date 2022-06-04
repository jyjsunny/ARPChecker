package APA.Transformers.ManualOp;

import APA.Transformers.AnalysisSteps.Step2Check;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.PCallChain;
import APA.Transformers.apiRelate.apiMethod;
import com.sun.codemodel.internal.JMethod;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

public class RevStepReport {
    public Map<apiMethod, Set<PCallChain>> requestMap = new HashMap<>();
    public Map<apiMethod, Set<PCallChain>> checkMap = new HashMap<>();
    public static RevStepReport reverseAnalyze() throws IOException {
        RevStepReport revReport = new RevStepReport();
        //check
        Set<PCallChain> checkResult = Step2Check.getCheckCallchains();
        //打印出check结果
        revReport.addCheckResult(checkResult);

        //request
        Set<PCallChain> requestResult = Step2Check.getRequestCallchains();
        revReport.addRequestResult(requestResult);






        return revReport;
    }

    private void addRequestResult(Set<PCallChain> requestResult) throws IOException {
        Map<apiMethod,Set<PCallChain>> map = new HashMap<>();
        for(PCallChain pc:requestResult)
        {
            if(!map.containsKey(pc.api))
                map.put(pc.api,new ConcurrentHashSet<>());
            map.get(pc.api).add(pc);
        }
        requestMap = map;
        //打印出checkChain结果
        new DumpablePResult(map, "request");
    }

    private void addCheckResult(Set<PCallChain> checkResult) throws IOException {
        Map<apiMethod,Set<PCallChain>> map = new HashMap<>();
        for(PCallChain pc:checkResult)
        {
            if(!map.containsKey(pc.api))
                map.put(pc.api,new ConcurrentHashSet<>());
            map.get(pc.api).add(pc);
        }
        checkMap = map;
        //打印出checkChain结果
        new DumpablePResult(map, "check");
    }
}

class DumpablePResult{

    public DumpablePResult(Map<apiMethod, Set<PCallChain>> map, String title) throws IOException {
        for(Map.Entry<apiMethod, Set<PCallChain>> it:map.entrySet())
        {
            //输出路径
            String fileName = title+"-"+apiMethod.printApiMethod(it.getKey())+".txt";
            Path path = Paths.get("revreports", fileName);
            List<String> content = new ArrayList<>();
            for(PCallChain pc: it.getValue())
            {
                content.add("-------------------------------");
                for(Permission p:pc.Permissions)
                {
                    content.add("["+p.toString()+"]");

                }
                for(apiMethod apim:pc.chain)
                {
                    content.add("  "+apiMethod.printApiMethod(apim));
                }

            }
            DoFiles.writeListTo(content, path.toString());
        }
    }
}
