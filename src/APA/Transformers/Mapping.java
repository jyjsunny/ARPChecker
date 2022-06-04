package APA.Transformers;


import APA.Transformers.ManualOp.DoFiles;
import APA.Transformers.PermissionRelate.Permission;
import APA.Transformers.PermissionRelate.PermissionCombination;
import APA.Transformers.apiRelate.apiMethod;
import soot.jimple.infoflow.collect.ConcurrentHashSet;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.util.*;

interface Mapping {
    static Mapping get(String aper, Path mappingPath, int apkTargetVersion) throws Throwable {
        return new ArpMapping(mappingPath.resolve("API"+apkTargetVersion));
    }

//    default ArpMethodMapMap getArpMethodMapOf(int tv) {
//        return ArpMethodMapMap.create(tv);
//    }
    Map<Permission, Set<apiMethod>> mapPermissionToMethods() throws IOException;
}
class ArpMapping implements Mapping {

    Path mappingPath ;
    public ArpMapping(Path mappingPath) throws Throwable {

        this.mappingPath = mappingPath;
        if (!mappingPath.toFile().isDirectory()) {
            throw new IOException("no such dir: " + mappingPath);
        }
    }

    @Override
    public Map<Permission, Set<apiMethod>> mapPermissionToMethods() throws IOException
    {
//        Map<String, Set<String>> mapStr = new HashMap<>();
        Map<Permission, Set<apiMethod>> map = new HashMap<>();
        //if(mappingPath.toFile().listFiles()!=null) {
            for (File file : Objects.requireNonNull(mappingPath.toFile().listFiles())) {
                if (!file.getName().endsWith("-Mappings.txt"))
                    continue;
                //对于每个以-Mapping.txt为末尾的文件进行逐行读取（annotations-Mappings和docs-Mappings）
                for (String line : DoFiles.readLinesFrom(file.getAbsolutePath())) {
                    List<String> parts = Arrays.asList(line.split(" :: "));//api::permissions::(anyof/allof)
                    String sig = parts.get(0);//sig: api接口所对应字符串
                    //拆分api、获取apiMethod
                    apiMethod method;
                    if (sig.contains("<"))//当api中包含<时
                        method = apiMethod.fromAxplorerSignature(sig.replaceAll("<.+?>", ""));
                    else
                        method = apiMethod.fromAxplorerSignature(sig);

                    String[] perms = parts.get(1).split(", ");//所需要权限
                    //如果有part[2]
                    if (parts.size() == 3) {
                        // parts[2] is either allOf or anyOf
                        PermissionCombination.put(method, parts.get(2));//用于存储method与所给的多个permissions之间的关系(any、all)
                    }
                    //遍历该行中的每一个permission
                    for (String perm : perms) {
                        if (perm.startsWith("android.permission.")) {
                            Permission permission = new Permission(perm);
                            boolean flag1 = false;//用于记录permission中是否已经包含了
                            for (Map.Entry<Permission, Set<apiMethod>> p_api : map.entrySet()) {
                                if (Objects.equals(p_api.getKey().toString(), permission.toString())) {
                                    flag1 = true;
                                    permission = p_api.getKey();
                                    break;
                                }
                            }
                            if (!flag1)
                                map.put(permission, new ConcurrentHashSet<>());

                            boolean flag2 = false;//用于记录set<apiMethod>中是否已经包含了apiMethod
                            for (apiMethod a : map.get(permission)) {
                                if (apiMethod.printApiMethod(a).equals(apiMethod.printApiMethod(method))) {
                                    flag2 = true;
                                    break;
                                }
                            }
                            if (!flag2)
                                map.get(permission).add(method);//把对应的method存入该permission的map组
                        }

                    }
                }


            }
        //}

        map = PscoutMapping.getDangerPAMapping(map);
        return map;

    }
}
class PscoutMapping implements Mapping
{

//    public static Set<Permission> getDangerousPermissions() throws IOException {
//        String filePath = Config.versionDangerousFile.toString();
//        Set<Permission> dPermissions = new ConcurrentHashSet<>();
//        for(String line: DoFiles.readLinesFrom(filePath))
//        {
//            Permission permission = new Permission(line);
//            dPermissions.add(permission);
//        }
//        return dPermissions;
//    }

    public static Map<Permission, Set<apiMethod>> getDangerPAMapping(Map<Permission, Set<apiMethod>> map) throws IOException {
        String filePath = Config.versionDangerousFile.toString();
        Set<Permission> dPermissions = new ConcurrentHashSet<>();
        for(String line: DoFiles.readLinesFrom(filePath))//dPermissions:存放所有28dangerous_permissions
        {
            Permission permission = new Permission(line);
            dPermissions.add(permission);
        }
        Map<Permission, Set<apiMethod>> resMap = new HashMap<>();//用于存放更新后的DangerPAMapping
        for (Map.Entry<Permission, Set<apiMethod>> p_api : map.entrySet())
        {
            for(Permission permission:dPermissions)
            {
                if(Objects.equals(permission.toString(),p_api.getKey().toString()))
                {
                    resMap.put(p_api.getKey(),p_api.getValue());
                }

            }
        }
        return resMap;
    }


    @Override
    public Map<Permission, Set<apiMethod>> mapPermissionToMethods() throws IOException {
        return null;
    }
}
















