package APA.Transformers;


import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.apiRelate.apiMethod;
import com.sun.codemodel.internal.JMethod;
import javafx.beans.binding.MapExpression;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class ArpMethodMapMap{
    private static Path mappingDir = Paths.get(Start.mappingPath);
//    private static Mapping mapping;
//
//    static {
//        try {
//            mapping = new ArpMapping(mappingDir.resolve("API_"+tv));//得到指定API下的mapping
//        } catch (Throwable e) {
//            e.printStackTrace();
//        }
//    }

    public ArpMethodMapMap(int rv) throws Throwable {

    }

    public static Map<apiMethod,Set<Permission>> getArpMethodMapOf(int tv) throws Throwable {
        return create(tv);
    }
    private static Map<Integer,Map<apiMethod,Set<Permission>>> store = new HashMap<>();
    public static Map<apiMethod, Set<Permission>> create(int rv) throws Throwable {
        if(store.containsKey(rv))
            return store.get(rv);
        //this, "Building ARP mapping for SDK-version {}", tv
        Map<apiMethod,Set<Permission>> newMap = arpMethodMapMap(rv);
        System.out.println("newMap:"+newMap.size());
        store.put(rv,newMap);
        return newMap;
    }
    //private static Map<apiMethod, Set<Permission>> ArpMethodMapMap = new HashMap<>();
    private static Map<apiMethod, Set<Permission>> arpMethodMapMap(int rv) throws Throwable {
        Map<apiMethod, Set<Permission>> ArpMethodMapMap = new HashMap<>();
        System.out.println("ArpMethodMapMap:"+ArpMethodMapMap.size());
        //得到该rv等级下所有的Map<Permission,Set<apiMethod>>
        Mapping mapping = new ArpMapping(mappingDir.resolve("API"+rv));
        for(Map.Entry<Permission,Set<apiMethod>> map:mapping.mapPermissionToMethods().entrySet())
        {
            for(apiMethod ap:map.getValue())
            {
                if(!ArpMethodMapMap.containsKey(ap)) {
                    ArpMethodMapMap.put(ap, new HashSet<>());
                    ArpMethodMapMap.get(ap).add(map.getKey());
                }
                else
                {
                    ArpMethodMapMap.get(ap).add(map.getKey());
                }
            }
        }
        System.out.println("ArpMethodMapMap:"+ArpMethodMapMap.size());
        return ArpMethodMapMap;
    }
}
