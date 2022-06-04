package APA.Transformers.apiRelate;

import java.util.Objects;

public class MaintainingAPI {
    public int id =0;

    public MaintainingAPI(String id) {
        if(Objects.equals(id, "C"))
            this.id = 1;
        if(Objects.equals(id, "R"))
            this.id = 2;
    }
}
