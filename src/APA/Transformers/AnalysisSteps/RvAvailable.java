package APA.Transformers.AnalysisSteps;

import soot.tagkit.AttributeValueException;
import soot.tagkit.Tag;

import java.util.HashMap;
import java.util.Map;

public class RvAvailable implements Tag {
    private static final Map<Integer, RvAvailable> cache = new HashMap<>();
    public final int rv;


    public  RvAvailable(int rv) {
        this.rv= rv;
    }

    public static RvAvailable tag(int rv) {
        if(!cache.containsKey(rv))
            cache.put(rv,new RvAvailable(rv));
        return cache.get(rv);
    }

    @Override
    public String getName() {
        return null;
    }

    @Override
    public byte[] getValue() throws AttributeValueException {
        return new byte[0];
    }
}
