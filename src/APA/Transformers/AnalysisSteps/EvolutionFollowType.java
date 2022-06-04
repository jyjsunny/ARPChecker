package APA.Transformers.AnalysisSteps;

public class EvolutionFollowType {
    public String typeName;
    public static EvolutionFollowType NoRvProtectedAPI = new EvolutionFollowType("Incompatible RV no Sentinal");
    public static EvolutionFollowType RvProtectedAPI = new EvolutionFollowType("Incompatible RV but Protected by Sentinal");
    public static EvolutionFollowType NoCR = new EvolutionFollowType("No CHECK/REQUEST");
    public static EvolutionFollowType OnlyC = new EvolutionFollowType("Only CHECK");
    public static EvolutionFollowType OnlyR = new EvolutionFollowType("Only REQUEST");
    public static EvolutionFollowType BothCR = new EvolutionFollowType("Both CHECK/REQUEST");
    public EvolutionFollowType(String explain) {
        this.typeName = explain;
    }
}
