package org.esperware.ghidramcp;

import ghidra.GhidraApplicationLayout;
import ghidra.GhidraClassLoader;
import ghidra.GhidraLaunchable;
import ghidra.GhidraLauncher;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;

/** Bootstrap loaded on AppClassLoader; adds server JARs into GhidraClassLoader before initializing Ghidra. */
public final class Bootstrap {
    public static void main(String[] args) throws Exception {
        if (!(ClassLoader.getSystemClassLoader() instanceof GhidraClassLoader loader)) {
            throw new IllegalStateException("Expected -Djava.system.class.loader=ghidra.GhidraClassLoader");
        }
        String libDirArg = System.getenv("GHIDRA_MCP_LIB_DIR");
        int startIdx = 0;
        if (args.length >= 2 && "--lib-dir".equals(args[0])) {
            libDirArg = args[1];
            startIdx = 2;
        }
        if (libDirArg == null || libDirArg.isBlank()) {
            throw new IllegalArgumentException("Missing --lib-dir or GHIDRA_MCP_LIB_DIR");
        }
        Path libDir = Path.of(libDirArg).toAbsolutePath().normalize();
        List<Path> jars;
        try (var stream = Files.list(libDir)) {
            jars = stream.filter(p -> p.getFileName().toString().endsWith(".jar"))
                    .sorted(Comparator.comparing(p -> p.getFileName().toString()))
                    .toList();
        }
        for (Path jar : jars) {
            loader.addPath(jar.toString());
        }

        GhidraApplicationLayout layout = GhidraLauncher.initializeGhidraEnvironment();
        Class<?> launcherClass = loader.loadClass("org.esperware.ghidramcp.GhidraMcpLauncher");
        GhidraLaunchable app = (GhidraLaunchable) launcherClass.getConstructor().newInstance();
        app.launch(layout, Arrays.copyOfRange(args, startIdx, args.length));
    }
}
