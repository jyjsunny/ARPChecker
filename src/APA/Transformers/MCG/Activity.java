package APA.Transformers.MCG;

import java.util.List;

public class Activity {
    public String name;
    public List<IntentFilter> intentFilter;

    public Activity(String name, List<IntentFilter> intentFilter) {
        this.name=name;
        this.intentFilter=intentFilter;
    }
}
