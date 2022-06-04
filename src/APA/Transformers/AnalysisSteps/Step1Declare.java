package APA.Transformers.AnalysisSteps;

import APA.Transformers.Config;
import APA.Transformers.ManualOp.DoFiles;
import APA.Transformers.PermissionRelate.Permission;

import java.io.IOException;
import java.util.*;

public class Step1Declare {
    public static void saveDeclaredPermissions(String filename) throws IOException {
        Set<Permission> allPermissions = Permission.getApkPermissions();
        Set<Permission> allDangerousPermissions = Permission.getApkDangerousPermissions();
        List<String> lines = new ArrayList<>();
        for(Permission p : allPermissions)
        {
            lines.add(p.toString());
        }
        lines.add(" ");
        lines.add("Declared Dangerous Permissions:");
        for(Permission p : allDangerousPermissions)
        {
            lines.add(p.toString());
        }
        DoFiles.writeListTo(lines, filename);
    }

    public static Map<Permission, Boolean> isPermissionDeclared(Set<Permission> permissions) throws IOException {
        Map<Permission, Boolean> p_d = new HashMap<>();
        Set<Permission> declaredPermissions = Permission.getApkDangerousPermissions();
        for(Permission p: permissions)
        {
            int flag = 0;
            for(Permission dp:declaredPermissions)
            {
                if(Objects.equals(dp.toString(), p.toString()))
                {
                    flag = 1;
                    break;
                }
            }
            if(flag==1)
                p_d.put(p,true);
            else
                p_d.put(p,false);

        }
        return p_d;
    }
}
