package APA.Transformers.ManualOp;

import APA.Transformers.AnalysisSteps.CheckSite;
import APA.Transformers.AnalysisSteps.RequestSite;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.DCallChain;
import APA.Transformers.apiRelate.apiMethod;
import com.sun.codemodel.internal.JMethod;
import com.sun.deploy.config.Config;
import com.sun.istack.internal.NotNull;
import javafx.util.Pair;
import soot.SootMethod;


import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class StepReport {
    private static int counter=0;//注意这里必须是private static int counter
    public int count;
    public apiMethod api;
    public List<apiMethod> chain;
    public Map<Permission, Boolean> declareRes;
    public Map<Permission, List<CheckSite>> checkRes;
    public Map<Permission,List<RequestSite>> requestRes;
    public Map<Permission, List<SootMethod>> handleRes;
    public Set<Permission> permissions;

    public StepReport(DCallChain _chain) {
        ++counter;
        this.count = counter;
        this.api = _chain.callChain.get(_chain.callChain.size()-1);//report:api接口
        this.chain = _chain.callChain;//report:危险callchain
        this.permissions = _chain.permissions;
    }

    public void addDeclareResult(Map<Permission, Boolean> declareR)
    {
        this.declareRes = declareR;

    }
    public void addCheckResult(Map<Permission, List<CheckSite>> checkR)
    {
        this.checkRes = checkR;
    }

    public void addRequestResult(Map<Permission, List<RequestSite>> requestR) {
        this.requestRes = requestR;
    }

    public void addHandleResult(Map<Permission, List<SootMethod>> handleRes) {
        this.handleRes = handleRes;
    }

}
