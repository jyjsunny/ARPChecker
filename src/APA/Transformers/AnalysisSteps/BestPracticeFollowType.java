package APA.Transformers.AnalysisSteps;

public class BestPracticeFollowType {
    public String typeName;
    public static BestPracticeFollowType PermissionNotDeclared = new BestPracticeFollowType("Permission Not Declared");
    public static BestPracticeFollowType OnlyDeclared = new BestPracticeFollowType("Only Declare Permission");

    public static BestPracticeFollowType NoCheck= new BestPracticeFollowType("No Check Step");
    // have check, flow-sensitive types
    public static BestPracticeFollowType CheckedInSequence= new BestPracticeFollowType("Use Check Before API");
    public static BestPracticeFollowType CheckNotInSequence= new BestPracticeFollowType("No Check Before API");

    public static BestPracticeFollowType NoRequest= new BestPracticeFollowType("No Request Step");
    // have request, path-sensitive types
    public static BestPracticeFollowType RequestedInSequence= new BestPracticeFollowType("Use Request If Not Granted");
    public static BestPracticeFollowType RequestNotInSequence= new BestPracticeFollowType("No Request If Not Granted");

    public static BestPracticeFollowType HandledInSequence= new BestPracticeFollowType("Correctly inside Handle");
    public static BestPracticeFollowType HandleNotInSequence= new BestPracticeFollowType("Not Used Correctly in Handle");

    public static BestPracticeFollowType UseFallbackHandle= new BestPracticeFollowType("Use Fallback onRequestPermissionsResult");
    // only check for whether permission is refered
    public static BestPracticeFollowType OverrideFallbackNoHandle= new BestPracticeFollowType("No Handle In Customized Fallback");
    public static BestPracticeFollowType OverrideFallbackWithHandle= new BestPracticeFollowType("Has Handle In Customized Fallback");

    public BestPracticeFollowType(String explain) {
        this.typeName = explain;
    }
}
