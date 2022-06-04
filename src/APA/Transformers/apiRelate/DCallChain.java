package APA.Transformers.apiRelate;

import APA.Transformers.PermissionRelate.Permission;

import java.util.List;
import java.util.Set;
/* Stands for Dangerous Call Chain */
public class DCallChain {
    public List<apiMethod> callChain;
    public Set<Permission> permissions;
    public DCallChain(List<apiMethod> callChain, Set<Permission> permissions) {
        this.callChain =callChain;
        this.permissions =permissions;
    }

    public static apiMethod getDangerousApis(DCallChain dangerousCallchain) {
            return dangerousCallchain.callChain.get(dangerousCallchain.callChain.size()-1);
    }


}
