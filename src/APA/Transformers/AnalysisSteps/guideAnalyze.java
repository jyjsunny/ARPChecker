package APA.Transformers.AnalysisSteps;

import APA.Transformers.ManualOp.DoFiles;
import APA.Transformers.ManualOp.StepReport;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.DCallChain;
import polyglot.main.Report;
import soot.SootMethod;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class guideAnalyze {
    public static Set<StepReport> analyze(Set<DCallChain> callchains) throws IOException {
        int idx=0;
        Set<StepReport> reportSet = new ConcurrentHashSet<>();
        for(DCallChain dc:callchains)
        {
            StepReport report = stepPipeline(dc);
            DoFiles.printReport(report);
            reportSet.add(report);
        }
        return reportSet;
    }

    private static StepReport stepPipeline(DCallChain chain) throws IOException {
        StepReport report = new StepReport(chain);//还没定义StepReport

        //Step1:检查DCallChain中需要的permission是否是该apk已经声明的危险apk
        Map<Permission, Boolean> step1result = Step1Declare.isPermissionDeclared(chain.permissions);
        report.addDeclareResult(step1result);//还没定义

        //Step2:根据DCallChain进行forward检查，查看每个危险api调用链在抵达最后dangerousApi之前是否含有对于指定permission的Check_Api
        Map<Permission, List<CheckSite>> step2result = Step2Check.findAllChecksites(chain);
        report.addCheckResult(step2result);

        //Step3:根据DCallChain进行forward检查，查看每个危险api调用链在抵达最后dangerousApi之前是否含有对于指定permission的Request_Api
        Map<Permission, List<RequestSite>> step3result = Step3Request.findAllRequestsites(chain);
        report.addRequestResult(step3result);

        //Step4:找到chain中每个handleSites
        Map<Permission, List<SootMethod>> step4result = Step4Handle.findHandleCallbacks(chain);
        report.addHandleResult(step4result);

        return  report;
    }
}
