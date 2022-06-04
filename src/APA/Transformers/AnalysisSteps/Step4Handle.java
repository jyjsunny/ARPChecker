package APA.Transformers.AnalysisSteps;

import APA.Transformers.Config;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.Type1Transformers.RDprblem;
import APA.Transformers.apiRelate.DCallChain;
import APA.Transformers.apiRelate.apiMethod;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.util.*;

public class Step4Handle {
    public static Map<Permission, List<SootMethod>> findHandleCallbacks(DCallChain chain) {
        Map<Permission, List<SootMethod>> res = new HashMap<>();
        for(Permission p: chain.permissions)
        {
            //对于chain中每个permission，handleSite用于存放它们所包含handle的sootmethod
            Set<SootMethod> handleSite = new LinkedHashSet<>();
            //forward find
            for(apiMethod apiMethod:chain.callChain)
            {
                //找到chain中每个apiMethod的回调处理方法
                SootMethod handle = findMemberHandlesite(apiMethod,p);
                if(handle != null)//此处list和set转换？区别？
                    handleSite.add(handle);
            }
            res.put(p,new ArrayList<>(handleSite));//返回一个chain中的所有lasthandle方法站点
        }
        return res;
    }

    private static SootMethod findMemberHandlesite(apiMethod method, Permission permission) {
        if(apiMethod.isBLACK(method))//black api中不包含回调处理
            return null;
        try {
            //加载该apiMethod所属的definingClass
            String className = method.definingClass.name;
            SootClass clazz = Scene.v().loadClassAndSupport(className);
            //加载该SootClass
            clazz = lastDefiningHandleClass(clazz);
            return clazz.getMethod(Config.HANDLE_API);//返回class关联的last定义的handle方法
        } catch (Exception e) {
            return null;//!
        }
    }

    private static SootClass lastDefiningHandleClass(SootClass clazz) {
        if(Objects.equals(clazz.getName(), "java.lang.Object"))//如果没有super类了
            return clazz;
        else if(clazz.declaresMethod(Config.HANDLE_API))//如果该类包含handle：HANDLE_API = "void onRequestPermissionsResult(int,java.lang.String[],int[])";
            return clazz;
        else
            return lastDefiningHandleClass(clazz.getSuperclass());
    }
}
