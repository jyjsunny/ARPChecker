package APA.Transformers.apiRelate;

import APA.Transformers.PermissionRelate.Permission;

import java.util.LinkedList;
import java.util.List;
import java.util.Set;
/* Stands for Permission Maintaining Call Chain */
public class PCallChain {
    public List<apiMethod> chain;
    public Set<Permission> Permissions;
    public apiMethod api;
    public PCallChain(List<apiMethod> checkChain, Set<Permission> saPermission) {
        this.chain = checkChain;
        this.Permissions = saPermission;
        api = this.chain.get(chain.size()-1);
    }
}
