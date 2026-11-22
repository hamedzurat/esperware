package org.esperware.ghidramcp;

import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ProgramExporterTest {
    @Test
    void normalizeSourcePathsStripsPrefixHandlesExternalDotDirsAndCollisions() {
        Map<String, String> single = ProgramExporter.normalizeSourcePaths(
                List.of("/home/alice/repo/src/readability-fixture.c"));
        assertEquals(Map.of(
                "/home/alice/repo/src/readability-fixture.c", "src/readability-fixture.c"), single);

        Map<String, String> multi = ProgramExporter.normalizeSourcePaths(List.of(
                "/home/alice/repo/src/main.c",
                "/home/alice/repo/src/net/parser.c",
                "/home/alice/repo/src/../include/types.h",
                "/home/alice/repo/src/.hidden/secret.c",
                "/usr/include/stdio.h",
                "<built-in>"));
        assertEquals("src/src/main.c", multi.get("/home/alice/repo/src/main.c"));
        assertEquals("src/src/net/parser.c", multi.get("/home/alice/repo/src/net/parser.c"));
        assertEquals("src/include/types.h", multi.get("/home/alice/repo/src/../include/types.h"));
        assertEquals("src/src/_hidden/secret.c", multi.get("/home/alice/repo/src/.hidden/secret.c"));
        assertEquals("src/_external/usr/include/stdio.h", multi.get("/usr/include/stdio.h"));
        assertEquals("src/_external/_built-in_", multi.get("<built-in>"));

        Map<String, String> traversal = ProgramExporter.normalizeSourcePaths(List.of(
                "../../outside/helper.c",
                "main.c"));
        assertEquals("src/outside/helper.c", traversal.get("../../outside/helper.c"));
        assertEquals("src/main.c", traversal.get("main.c"));

        Map<String, String> collisions = ProgramExporter.normalizeSourcePaths(List.of(
                "/work/proj/foo bar.c",
                "/work/proj/foo:bar.c"));
        assertEquals("src/foo_bar.c", collisions.get("/work/proj/foo bar.c"));
        assertEquals("src/foo_bar_2.c", collisions.get("/work/proj/foo:bar.c"));
    }

    @Test
    void normalizeSourcePathsKeepsFilesAndDirectoriesDistinct() {
        Map<String, String> fileFirst = ProgramExporter.normalizeSourcePaths(List.of(
                "dir name", "dir:name/one.c", "dir:name/two.c"));
        assertEquals("src/dir_name", fileFirst.get("dir name"));
        assertEquals("src/dir_name_2/one.c", fileFirst.get("dir:name/one.c"));
        assertEquals("src/dir_name_2/two.c", fileFirst.get("dir:name/two.c"));

        Map<String, String> directoryFirst = ProgramExporter.normalizeSourcePaths(List.of(
                "dir name/one.c", "dir:name"));
        assertEquals("src/dir_name/one.c", directoryFirst.get("dir name/one.c"));
        assertEquals("src/dir_name_2", directoryFirst.get("dir:name"));
    }

    @Test
    void classifyFallbackSourceRoutesNamespaceTextAndSections() {
        assertEquals("src/_ns/Net/Parser.c",
                ProgramExporter.classifyFallbackSource(List.of("Net", "Parser"), ".text", "00401100"));
        assertEquals("src/_text/00401129.c",
                ProgramExporter.classifyFallbackSource(List.of(), ".text", "00401129"));
        assertEquals("src/_text/ram_00401129.c",
                ProgramExporter.classifyFallbackSource(List.of(), "__text", "ram:00401129"));
        assertEquals("src/_sec/init.c",
                ProgramExporter.classifyFallbackSource(List.of(), ".init", "00401000"));
        assertEquals("src/_sec/plt.got.c",
                ProgramExporter.classifyFallbackSource(List.of(), ".plt.got", "00401030"));
        assertEquals("src/_sec/unknown.c",
                ProgramExporter.classifyFallbackSource(List.of(), null, "00401040"));
    }
}
