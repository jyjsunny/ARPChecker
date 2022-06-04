package APA.Transformers.ManualOp;


import APA.Transformers.apiRelate.apiMethod;

import java.util.LinkedList;

public interface Visitor {
    public default void happly(LinkedList<apiMethod> chain)
    {

    }

}
