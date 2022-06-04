package APA.Transformers.apiRelate;

import APA.Transformers.Config;
import APA.Transformers.ManualOp.Visitor;
import APA.Transformers.PermissionRelate.Permission;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class apiMethod {
    public String methodName;
    public apiClass definingClass;
    public apiClass retClass;
    public List<apiClass> paramClasses;
    private static final Pattern AXP_METHOD_PATTERN= Pattern.compile("^(.*?)\\.(\\w+)\\((.*?)\\)(.*?)$");
    private static final Pattern SOOT_METHOD_PATTERN = Pattern.compile("^<(.+?): (.+?) (.+?)\\((.*?)\\)>$");

    public apiMethod(String methodName, apiClass definingClass, apiClass retClass, List<apiClass> paramClasses) {
        this.methodName = methodName;
        this.definingClass = definingClass;
        this.retClass = retClass;
        this.paramClasses = paramClasses;
    }



    public static apiMethod fromAxplorerSignature(String sig)
    {
        Matcher m = AXP_METHOD_PATTERN.matcher(sig);
        if(!(m.find()))
            throw new IllegalArgumentException("not a valid method: $sig");
        else
        {
            String method = m.group(2);
            apiClass definingClass = new apiClass(m.group(1));
            apiClass retClass = new apiClass(m.group(4));//函数type
            //拆分（）里的东西
            String s3 = m.group(3);
            String[] s33 = s3.split(",");
            List<apiClass> paramClasses = new ArrayList<>();
            for(String s: s33)
            {
                apiClass a = new apiClass(s);
                paramClasses.add(a);
            }

            return new apiMethod(method, definingClass, retClass, paramClasses);
        }
    }

    public static apiMethod fromSootSignature(String signature) {
        Matcher m = SOOT_METHOD_PATTERN.matcher(signature);
        if(!(m.find()))
            throw new IllegalArgumentException("not a valid method: $sig");
        else
        {
            String method = m.group(3);
            apiClass definingClass = new apiClass(m.group(1));
            apiClass retClass = new apiClass(m.group(2));//函数type
            //拆分（）里的东西
            String s3 = m.group(4);
            String[] s33 = s3.split(",");
            List<apiClass> paramClasses = new ArrayList<>();
            for(String s: s33)
            {
                apiClass a = new apiClass(s);
                paramClasses.add(a);
            }

            return new apiMethod(method, definingClass, retClass, paramClasses);
        }
    }


    public static String printApiMethod(apiMethod key) {//用于打印apimethod的全称
        StringBuilder res = new StringBuilder();
        List<String> r = new ArrayList<>();
        r.add("<");
        r.add(key.definingClass.name);
        r.add(": ");
        r.add(key.retClass.name);
        r.add(" ");
        r.add(key.methodName);
        r.add("(");
        int i=0;
        for(apiClass a:key.paramClasses)
        {
            r.add(a.name);
            i++;
            if(i!=key.paramClasses.size())
                r.add(",");
        }
        r.add(")");
        r.add(">");
        for(String s:r) {
            res.append(s);
        }
        return res.toString();
    }

    public static String printSubsignature(apiMethod key) {
        StringBuilder res = new StringBuilder();
        List<String> r = new ArrayList<>();
        r.add(key.retClass.name);
        r.add(" ");
        r.add(key.methodName);
        r.add("(");
        int i=0;
        for(apiClass a:key.paramClasses)
        {
            r.add(a.name);
            i++;
            if(i!=key.paramClasses.size())
                r.add(",");
        }
        r.add(")");
        for(String s:r) {
            res.append(s);
        }
        return res.toString();
    }

    public static String printSignature(apiMethod key) {
        StringBuilder res = new StringBuilder();
        List<String> r = new ArrayList<>();
        r.add("<");
        r.add(key.definingClass.name);
        r.add(": ");
        r.add(key.retClass.name);
        r.add(" ");
        r.add(key.methodName);
        r.add("(");
        int i=0;
        for(apiClass a:key.paramClasses)
        {
            r.add(a.name);
            i++;
            if(i!=key.paramClasses.size())
                r.add(",");
        }
        r.add(")");
        r.add(">");
        for(String s:r) {
            res.append(s);
        }
        return res.toString();
    }

    public static LinkedList<apiMethod> collectCallchainsTo(apiMethod method,Visitor visitor) {
        LinkedList<apiMethod> currentChain = new LinkedList<>();
        currentChain.addFirst(method);
        CallChain.travelCallGraph(currentChain, new ConcurrentHashSet<>(),visitor);
        return currentChain;
    }

    public static boolean isBLACK(apiMethod method) {
        for(int i = 0; i< Config.BLACK_LIST.size(); i++)
        {
            if(method.definingClass.name.startsWith(Config.BLACK_LIST.get(i)))
                return true;
        }
        return false;
    }


}
