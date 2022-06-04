package APA.Transformers.ManualOp;

import soot.SootMethod;

public class DoClasses {
    public static  boolean isHandleApi(SootMethod sootMethod) {
        return (sootMethod.getSubSignature().equals("void onRequestPermissionsResult(int,java.lang.String[],int[])"));
    }
}
