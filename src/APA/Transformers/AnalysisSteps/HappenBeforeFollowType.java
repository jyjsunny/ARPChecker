package APA.Transformers.AnalysisSteps;

public class HappenBeforeFollowType {
    public String typeName;
    public static HappenBeforeFollowType NoDeclareAndNoSteps = new HappenBeforeFollowType("No Declare And No Steps");
    public static HappenBeforeFollowType NoDeclareWithSteps = new HappenBeforeFollowType("Not Declared But Has CHECK/REQUEST");
    public static HappenBeforeFollowType DeclaredNoSteps = new HappenBeforeFollowType("Only Declared And No CHECK/REQUEST");

    public static HappenBeforeFollowType SyncCheckedAlready = new HappenBeforeFollowType("Check Synchronously Already");
    public static HappenBeforeFollowType AsyncCheckBeforeUse = new HappenBeforeFollowType("Check Asynchronously Before Use API");
    public static HappenBeforeFollowType NoAsyncCheckBeforeUse = new HappenBeforeFollowType("No Asynchronous Check Before Use API");
    public static HappenBeforeFollowType IsHandleNoCheck = new HappenBeforeFollowType("No Check Because Is Handle API");

    public static HappenBeforeFollowType SyncRequestedAlready = new HappenBeforeFollowType("Request Synchronously Already");
    public static HappenBeforeFollowType AsyncRequestBeforeUse = new HappenBeforeFollowType("Request Asynchronously Before Use API");
    public static HappenBeforeFollowType NoAsyncRequestBeforeUse = new HappenBeforeFollowType("No Asynchronous Request Before Use API");

    public HappenBeforeFollowType(String explain) {
        this.typeName = explain;
    }
}
