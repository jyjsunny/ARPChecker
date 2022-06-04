package APA.Transformers.apiRelate;

public class apiClass {
    public String name;
    public String shortName;
    public String packageId;
    public apiClass(String name) {
        if(name!=null)
        {
            this.name = name;
            String[] s=name.split("\\.");
            this.shortName = s[(s.length-1)];//返回最后一次出现分隔符之后的子字符串
//            this.packageId=name.substring(0,(s.length-shortName.length()-1));//返回最后一次出现分隔符之前的子字符串
        }


    }

}
