package APA.Transformers.ManualOp;

import soot.SootMethod;
import soot.Value;
import soot.jimple.InvokeStmt;
import sun.awt.HKSCS;

import java.util.*;

public class SignatureUtil {

    private static List<String> moduleInteractionMethodName =Arrays.asList(
        "startActivity",
        "startActivityForResult",
        "startActivityFromChild",
        "startActivityFromFragment",
        "startActivityIfNeeded",
        "startService",
        "bindService",
        "startForegroundService",
        "sendBroadcast",
        "sendBroadcastAsUser",
        "sendOrderedBroadcast",
        "sendOrderedBroadcastAsUser",
        "sendStickyBroadcast",
        "sendStickyBroadcastAsUser",
        "sendStickyOrderedBroadcast",
        "sendStickyOrderedBroadcastAsUser"
    );
    public static SigParseResult parseIntentArg(InvokeStmt stmt) {
        //handle list of Intent
        SootMethod method = stmt.getInvokeExpr().getMethod();//stmt调用的sootMethod
        List<Value> args = stmt.getInvokeExpr().getArgs();//stmt调用语句中的方法参数
        //检查是不是一个用于登记broadcast receiver的API
        if (Objects.equals(method.getName(), "registerReceiver") && args.size() >= 2 && Objects.equals(args.get(1).getType().toString(), "android.content.IntentFilter")) {
            return new SigParseResult(true, args.get(1).toString(), method.getName());
        }
        //检查是不是一个用于start Activity, Service, BroadCast的API
        if (moduleInteractionMethodName.contains(method.getName())) {
            //Returns the single element matching the given predicate, or throws exception if there is no or more than one matching element.
            String index = null;
            int i=0;
            for(Value v:args)
            {
                if(v.getType().toString()=="android.content.Intent")
                {
                    i++;
                    if(i==1)
                        index = v.toString();
                }
            }
            if(i ==1)
                return new SigParseResult(false, index, method.getName());
        }
        return null;
    }
}
