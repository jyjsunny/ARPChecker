package APA.Transformers.AnalysisSteps;

import APA.Transformers.apiRelate.MaintainingAPI;

import java.nio.file.Path;
import java.util.HashSet;
import java.util.Set;

public class EmpiricalAnalyzer {
    private static final Set<Path> intraProcedureC = new HashSet<>();
    private static final Set<Path> intraProcedureR = new HashSet<>();

    private static final Set<Path> interProcedureC = new HashSet<>();
    private static final Set<Path> interProcedureR = new HashSet<>();

    private static final Set<Path> interLifecycleC = new HashSet<>();
    private static final Set<Path> interLifecycleR = new HashSet<>();

    private static final Set<Path> interComponentC = new HashSet<>();
    private static final Set<Path> interComponentR = new HashSet<>();

    private static final Set<Path> incomplete = new HashSet<>();

    private static void addTo(Set<Path> ccol, Set<Path> rcol, Path report, MaintainingAPI idApi) {
        if(idApi.id==1)
            ccol.add(report);
        if(idApi.id==2)
            rcol.add(report);
    }

    public static void addIntraProcedure(Path report, MaintainingAPI idApi) {
        addTo(intraProcedureC, intraProcedureR, report, idApi);
    }


    public static void addInterProcedure(Path report, MaintainingAPI idApi) {
        addTo(interProcedureC, interProcedureR,report, idApi);
    }

    public static void addInterLifecycle(Path report, MaintainingAPI idApi) {
        addTo(interLifecycleC, interLifecycleR,report, idApi);
    }

    public static void addInterComponent(Path report, MaintainingAPI idApi) {
        addTo(interComponentC, interComponentR,report, idApi);
    }

    public static void addIncomplete(Path report) {
        incomplete.add(report);
    }
}
