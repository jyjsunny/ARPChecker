package APA.Transformers.apiRelate;



import APA.Transformers.CG;
import APA.Transformers.Config;
import APA.Transformers.PermissionRelate.Permission;
import heros.solver.Pair;
import soot.SootMethod;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.util.*;

public class api {
    public static final Map<apiMethod,Set<Permission>> apiToDangerousPermissions = new HashMap<>();

    public static Map<apiMethod, Set<Permission>> getDangerousApis(Map<Permission, Set<apiMethod>> allPermissionToApis)
    {
        if(!apiToDangerousPermissions.isEmpty())
            return apiToDangerousPermissions;

        Map<apiMethod,Set<Permission>> apiToPermissions = getApiToPermissions(allPermissionToApis);//Map<apiMethod,Set<Permission>>
        for (Map.Entry<apiMethod, Set<Permission>> apiMethodSetEntry : apiToPermissions.entrySet())
        {
            apiMethod method = apiMethodSetEntry.getKey();
            Set<Permission> permissions = apiMethodSetEntry.getValue();

            if (!apiToDangerousPermissions.containsKey(method)) {
                apiToDangerousPermissions.put(method, new ConcurrentHashSet<>());
            }
            apiToDangerousPermissions.put(method,permissions);

        }
        return apiToDangerousPermissions;
    }

    private static Map<apiMethod, Set<Permission>> getApiToPermissions(Map<Permission, Set<apiMethod>> allPermissionToApis) {
        Map<apiMethod,Set<Permission>> apiToPermissions =new HashMap<>();
        Iterator<Pair<SootMethod, SootMethod>> edges = CG.getAllEdges();//找到apk内的相关api-permission
        Pair<SootMethod, SootMethod> edgePair;
        //遍历CG中的每一条edge
        while(edges.hasNext())
        {
            edgePair = edges.next();
            if(!isSupport(edgePair.getO1()))//不记录SUPPORT_LIST里的
            {
                apiMethod  method= apiMethod.fromSootSignature(edgePair.getO2().getSignature());//通过edge.tail.signature把sootMethod重新定义成指向的apiMethod
                //遍历allPermissionToApis
                for (Map.Entry<Permission, Set<apiMethod>> pSa : allPermissionToApis.entrySet())
                {
                    for(apiMethod api:pSa.getValue())
                    {//只要有一条CG中边的tail==pSa的Set<apiMethod>中的一个
                        if(Objects.equals(apiMethod.printApiMethod(api),apiMethod.printApiMethod(method)))//错误：api.methodName==method.methodName
                        {
                            boolean flag = false;//判断该apiMethod是否已经在apiToPermissions的key中
                            for (Map.Entry<apiMethod, Set<Permission>> api_p : apiToPermissions.entrySet())
                            {
                                if(Objects.equals(apiMethod.printApiMethod(api_p.getKey()), apiMethod.printApiMethod(method)))
                                {
                                    flag=true;
                                    method = api_p.getKey();
                                    break;
                                }
                            }
                            if(!flag)
                                apiToPermissions.put(method,new ConcurrentHashSet<>());
                            apiToPermissions.get(method).add(pSa.getKey());
                        }
                    }
                }
            }
        }
        return apiToPermissions;
    }







    public static boolean isSupport(SootMethod sootMethod) {
        for(int i = 0; i< Config.SUPPORT_LIST.size(); i++)
        {
            if(sootMethod.getDeclaringClass().getName().startsWith(Config.SUPPORT_LIST.get(i)))
                return true;
        }
        return false;
    }
}
