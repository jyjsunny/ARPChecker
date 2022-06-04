package APA.Transformers;


import net.dongliu.apk.parser.ApkFile;
import net.dongliu.apk.parser.bean.ApkMeta;
import org.apache.commons.io.IOUtils;
import soot.Scene;
import soot.SootClass;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Config {
    public static final String ABS_CHECK = "<android.content.Context: int checkSelfPermission(java.lang.String)>";
    public static final String ALTER_CHECK = "<android.content.ContextWrapper: int checkSelfPermission(java.lang.String)>";
    public static final String SDK_INT_FIELD = "<android.os.Build$VERSION: int SDK_INT>";
    public static Path apkOutputDir;
    public static Path versionSdkFile;
    public static Path versionDangerousFile;
    public static Path androidCallbacksFile;
    public static List<String> excludedPkgs;
    public static int apkTargetVersion;
    public static String apkPackageName;
    public static String apkPath;
    public static ApkFile apkFile;
    public static ApkMeta apkMeta;
    public static Set<String> permissions;


    public static Path outputDir = Paths.get("analyzerOutput/");
    public static Path androidJarDir = Paths.get(Start.androidSdkJarPath);

    //public static SootClass RUNNABLE_CLASS= Scene.v().getSootClass("java.lang.Runnable");
    public static List<String> BLACK_LIST = Arrays.asList("android.", "androidx.", "com.android.", "com.google.android.", "java.", "javax.", "kotlin.", "kotlinx.", "io.reactivex.", "rx.");;
    public static List<String> SUPPORT_LIST= Arrays.asList("android.support.", "androidx.");
    public static List<String> CHECK_APIS = Arrays.asList(
                // all implemented CHECK apis
                "<android.support.v4.content.ContextCompat: int checkSelfPermission(android.content.Context,java.lang.String)>",
                "<androidx.core.content.ContextCompat: int checkSelfPermission(android.content.Context,java.lang.String)>",

                // not supported for backward-compatibility
                "<android.content.ContextWrapper: int checkSelfPermission(java.lang.String)>",
                "<android.content.Context: int checkSelfPermission(java.lang.String)>",

                // legacy api
                "<android.support.v4.content.PermissionChecker: int checkSelfPermission(android.content.Context,java.lang.String)>",
                "<androidx.code.content.PermissionChecker: int checkSelfPermission(android.content.Context,java.lang.String)>"
    );
    public static List<String> REQUEST_APIS = Arrays.asList(
            // implemented REQUEST apis for activity
            "<android.app.Activity: void requestPermissions(java.lang.String[],int)>",
            "<android.support.v4.app.ActivityCompat: void requestPermissions(android.app.Activity,java.lang.String[],int)>",
            "<androidx.core.app.ActivityCompat: void requestPermissions(android.app.Activity,java.lang.String[],int)>",

            // implemented REQUEST apis for fragment
            "<android.support.v4.app.Fragment: void requestPermissions(java.lang.String[],int)>",   // before androidx
            "<androidx.fragment.app.Fragment: void requestPermissions(java.lang.String[],int)>",    // androidx migrations for previous
            // the later two are not recommanded
            "<android.app.Fragment: void requestPermissions(java.lang.String[],int)>",              // deprecatd
            "<android.support.v13.app.FragmentCompat: void requestPermissions(android.app.Fragment,java.lang.String[],int)>"    // no appear in androidx
    );
    public static String HANDLE_API = "void onRequestPermissionsResult(int,java.lang.String[],int[])";

    //public static int targetSdkVersion = (apkMeta.getTargetSdkVersion()!=null)? Integer.parseInt(apkMeta.getTargetSdkVersion()):-1;
    public static int minSdkVersion ;//= (apkMeta.getMinSdkVersion()!=null)? Integer.parseInt(apkMeta.getMinSdkVersion()):-1;


    public static void init() throws IOException {

        apkPath = Start.apkPath;
        apkFile = new ApkFile(apkPath);
        apkMeta = apkFile.getApkMeta();
        minSdkVersion = Integer.parseInt(apkMeta.getMinSdkVersion());
        apkTargetVersion = Integer.parseInt(apkMeta.getTargetSdkVersion());
        apkPackageName = apkMeta.getPackageName();

        apkOutputDir = outputDir.resolve(apkPackageName);
        versionDangerousFile = copyToTemp(apkTargetVersion+"Dangerous.txt");//
        versionSdkFile = androidJarDir.resolve("android-"+apkTargetVersion).resolve("android.jar");
        androidCallbacksFile = copyToTemp("AndroidCallbacks.txt");
//exLibs
        InputStream exlist = Config.class.getClassLoader().getResourceAsStream("exclude_list.txt");
        assert exlist != null;
        excludedPkgs = IOUtils.readLines(exlist, Charset.defaultCharset());
        permissions = new HashSet<>(apkMeta.getUsesPermissions());//用于存储该APIversion下定义的所有usersPermission

    }

    public static Path copyToTemp(String s) throws IOException {
        InputStream in = Config.class.getClassLoader().getResourceAsStream("arpcompat/"+s);
        if(in == null) {
            throw new IOException("no such dir: "+s);
        }
        File temp = File.createTempFile("arpcompat-", ".txt");
        IOUtils.copy(in, new FileOutputStream(temp));
        return temp.toPath();
    }

}
