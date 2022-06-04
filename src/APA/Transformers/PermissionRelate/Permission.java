package APA.Transformers.PermissionRelate;

import APA.Transformers.Config;
import APA.Transformers.ManualOp.DoFiles;

import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;

public final class Permission {
    private final String name;
    private static Set<Permission> apkPermissions = null;
    private static Set<Permission> apkDangerousPermissions = null;

    public Permission(String _name) {
        this.name = _name;
    }

    public static boolean isPermissionString(String value) {
        return true;
    }

    public String toString()
    {
        return this.name;
    }
    public static Set<Permission> getApkPermissions() {
        if(apkPermissions==null)
        {
            //使用APKMeta获得指定apk的manifest中的permissions
            apkPermissions = new HashSet<>();
            for(String s: Config.permissions)
            {
                Permission p = new Permission(s);
                apkPermissions.add(p);
            }
        }
        return apkPermissions;
    }
    public static Set<Permission> getApkDangerousPermissions() throws IOException {
        if(apkDangerousPermissions==null)
        {
            apkDangerousPermissions = new HashSet<>();
            Set<Permission> allDangerous = new HashSet<>();//用于存放该API等级下的所有dangerous permissions
            String filePath = Config.versionDangerousFile.toString();
            List<String> lines = DoFiles.readLinesFrom(filePath);
            for(String s:lines)
            {
                //System.out.println(s);
                Permission p = new Permission(s);
                //System.out.println(p.name);
                allDangerous.add(p);
            }

            for(Permission p: apkPermissions)
            {
                for (Permission q: allDangerous)
                {
                    if(Objects.equals(p.name, q.name))
                    {
                       // System.out.println(p.name);
                        apkDangerousPermissions.add(p);
                    }

                }
            }

        }
        return apkDangerousPermissions;
    }
}
