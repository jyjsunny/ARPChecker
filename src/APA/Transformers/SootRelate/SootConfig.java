package APA.Transformers.SootRelate;

import APA.Transformers.Config;
import soot.Scene;
import soot.SootClass;
import soot.options.Options;

import java.util.Collections;

public class SootConfig {
    public static void setupSoot(Scene scene) {
        soot.G.reset();
        scene.setSootClassPath(Config.versionSdkFile.toString());
        Options.v().set_soot_classpath(Config.versionSdkFile.toString());

        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(true);
        Options.v().set_prepend_classpath(true);
        Options.v().set_process_multiple_dex(true);
        Options.v().set_validate(true);

//        Options.v().set_exclude(Config.excludedPkgs);
//        Options.v().set_no_bodies_for_excluded(true);
////
        //
        Options.v().set_force_android_jar(Config.versionSdkFile.toString());
        //Options.v().set_soot_classpath(Config.versionSdkFile.toString());
        Options.v().set_process_dir(Collections.singletonList(Config.apkPath));
        Options.v().set_src_prec(Options.src_prec_apk);
        Options.v().set_output_format(Options.output_format_dex);

//

    }

//    public static void apply_options(Scene sc) {
//        Options.v().set_exclude(Config.excludedPkgs);
//        Options.v().set_no_bodies_for_excluded(true);
////
//        Options.v().set_force_android_jar(Config.versionSdkFile.toString());
//        Options.v().set_soot_classpath(Config.versionSdkFile.toString());
//        Options.v().set_process_dir(Collections.singletonList(Config.apkPath));
//        Options.v().set_src_prec(Options.src_prec_apk);
//        Options.v().set_output_format(Options.output_format_dex);
//    }
}
