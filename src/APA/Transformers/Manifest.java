package APA.Transformers;

import APA.Transformers.Intent.IntentAction;
import APA.Transformers.Intent.IntentCategory;
import APA.Transformers.Intent.IntentData;
import APA.Transformers.MCG.*;
import org.dom4j.*;


import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Manifest {


    public ArrayList<Receiver> receiver = new ArrayList<>();
    public ArrayList<Service> service = new ArrayList<>();
    public ArrayList<Activity> activity = new ArrayList<>();

    public static Element root;
    public static Element application ;
    public static String pack;

    public Manifest(String text) throws DocumentException {
        Document document = DocumentHelper.parseText(text);
        root = document.getRootElement();
        application = root.element("application");
        pack = root.attributeValue("package");

    }

    public Manifest(List<Activity> activity, List<ActivityAlias> activityAlias, List<Service> service, List<Receiver> receiver, List<Provider> provider) {
            this.receiver.addAll(receiver);
            this.service.addAll(service);
            this.activity.addAll(activity);

    }
    public Set<String> getNames() {
        Set<String> maniName = new HashSet<>();
        for(Activity a:activity) {
            maniName.add(a.name);
        }
        for(Service s:service)
        {
            maniName.add(s.name);
        }
        for(Receiver r:receiver)
        {
            maniName.add(r.name);
        }
        return maniName;
    }

    public static Manifest parse(Manifest manifest){
        List<Activity> activity = parseActivity();
        List<ActivityAlias> activityAlias = parseActivityAlias();
        List<Service> service = parseService();
        List<Receiver> receiver = parseReceiver();
        List<Provider> provider = parseProvider();
        return new Manifest(activity, activityAlias, service, receiver, provider);
    }

    private static List<Provider> parseProvider() {
        List<Provider> providers = new ArrayList<>();
        for(Object o:application.elements("provider"))
        {
            Element provider = (Element) o;
            String name = getComponentName(provider);//记录activity的组件名

            providers.add(new Provider(name));
        }
        return providers;

    }

    private static List<Receiver> parseReceiver() {
        List<Receiver> receivers = new ArrayList<>();
        for(Object o:application.elements("receiver"))
        {
            Element receiver = (Element) o;
            String name = getComponentName(receiver);//记录activity的组件名
            List<IntentFilter> intentFilter = parseIntentFilter(receiver);

            receivers.add(new Receiver(name, intentFilter));
        }
        return receivers;
    }

    private static List<Service> parseService() {
        List<Service> services = new ArrayList<>();
        for(Object o:application.elements("service"))
        {
            Element service = (Element) o;
            String name = getComponentName(service);//记录activity的组件名
            List<IntentFilter> intentFilter = parseIntentFilter(service);

            services.add(new Service(name, intentFilter));
        }
        return services;

    }

    private static List<ActivityAlias> parseActivityAlias() {
        List<ActivityAlias> alias = new ArrayList<>();
        for(Object o:application.elements("activity-alias"))
        {
            Element alia = (Element) o;
            String name = getComponentName(alia);//记录alia的组件名
            String attribute = "targetActivity";
            String targetActivity = getComponentName(alia, attribute);
            List<IntentFilter> intentFilter = parseIntentFilter(alia);

            alias.add(new ActivityAlias(name, targetActivity, intentFilter));
        }
        return alias;

    }

    private static String getComponentName(Element element, String attribute) {
        String l = element.attributeValue(attribute);
        if(l.startsWith("."))
            return pack+l;//如果带"."记得加上rootElement的包名称
        else
            return l;
    }

    private static List<Activity> parseActivity() {
        List<Activity> activities = new ArrayList<>();
        for(Object o:application.elements("activity"))
        {
            Element activity = (Element) o;
            String name = getComponentName(activity);//记录activity的组件名
            List<IntentFilter> intentFilter = parseIntentFilter(activity);

            activities.add(new Activity(name, intentFilter));
        }
        return activities;

    }

    private static List<IntentFilter> parseIntentFilter(Element element) {
        List<IntentFilter> itfs = new ArrayList<>();
        for(Object o:element.elements("intent-filter"))
        {
            Element filter = (Element) o;
            List<IntentAction> actions =new ArrayList<>();
            for(Object o2:filter.elements("action"))
            {
                Element action = (Element) o2;
                actions.add(new IntentAction(attrNamespace(action,"name")));
            }
            List<IntentCategory> categories =new ArrayList<>();
            for(Object o2:filter.elements("category"))
            {
                Element category = (Element) o2;
                categories.add(new IntentCategory(attrNamespace(category,"name")));
            }
            List<IntentData> datas =new ArrayList<>();
            for(Object o2:filter.elements("category"))
            {
                Element data = (Element) o2;
                String scheme = "";
                String host = "";
                String port = "";
                String path = "";
                String pathPattern = "";
                String pathPrefix = "";
                String mimeType = "";
                datas.add(new IntentData(attrNamespace(data,scheme),attrNamespace(data,host),attrNamespace(data,port),attrNamespace(data,path),attrNamespace(data,pathPattern),attrNamespace(data,pathPrefix),attrNamespace(data,mimeType)));
            }
            itfs.add(new IntentFilter(actions, categories, datas));
        }
        return itfs;
    }

    private static String attrNamespace(Element element, String name) {
        Namespace namespace = new Namespace("android", "http://schemas.android.com/apk/res/android");
        return element.attributeValue(QName.get(name, namespace));
    }

    private static String getComponentName(Element element) {
        String l = element.attributeValue("name");
        if(l.startsWith("."))
            return pack+l;//如果带"."记得加上rootElement的包名称
        else
            return l;

    }


    public void addReceiver(Receiver receiver) {
        this.receiver.add(receiver);
    }
}
