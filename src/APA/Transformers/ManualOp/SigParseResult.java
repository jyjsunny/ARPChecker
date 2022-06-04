package APA.Transformers.ManualOp;

public class SigParseResult {
    public Boolean isBCReceiver;
    public String identifier;
    public String apiName;
    public SigParseResult(boolean b, String toString, String name) {
        this.isBCReceiver = b;
        this.identifier = toString;
        this.apiName = name;
    }
}
