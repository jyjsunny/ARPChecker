package APA.Transformers.PermissionRelate;

import APA.Transformers.apiRelate.apiMethod;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class PermissionCombination {
    public static PermissionCombination AnyOf;
    public static PermissionCombination AllOf;
    private static Map<apiMethod,PermissionCombination> combinationType = new HashMap<>();
    public static void put(apiMethod method, String type) {
        if(Objects.equals(type, "anyOf"))
            combinationType.put(method,AnyOf);
        else if(Objects.equals(type, "allOf"))
            combinationType.put(method,AllOf);
    }

    public static PermissionCombination get(apiMethod method) {
        return combinationType.put(method,AnyOf);  // fallback since any is majority
    }
}
