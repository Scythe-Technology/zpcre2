const std = @import("std");

const Build = std.Build;
const Step = std.Build.Step;

pub fn build(b: *Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const pcre2 = buildPCRE2(b, target, optimize);

    const module = b.addModule("zpcre2", .{
        .root_source_file = b.path("src/lib.zig"),
    });
    module.linkLibrary(pcre2);

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/lib.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    tests.root_module.linkLibrary(pcre2);

    const run_tests = b.addRunArtifact(tests);

    const test_step = b.step("test", "Run zig-luau tests");

    test_step.dependOn(&run_tests.step);
}

pub fn buildPCRE2(
    b: *Build,
    target: Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) *Build.Step.Compile {
    const lib = b.addLibrary(.{
        .name = "pcre2",
        .linkage = .static,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
        }),
    });
    lib.linkLibC();

    const config_header = b.addConfigHeader(.{
        .style = .{
            .cmake = b.path("pcre2/src/config-cmake.h.in"),
        },
        .include_path = "config.h",
    }, .{
        .HAVE_ASSERT_H = true,
        .HAVE_UNISTD_H = (target.result.os.tag != .windows),
        .HAVE_WINDOWS_H = (target.result.os.tag == .windows),

        .HAVE_MEMMOVE = true,
        .HAVE_STRERROR = true,

        .SUPPORT_PCRE2_8 = true,
        .SUPPORT_PCRE2_16 = false,
        .SUPPORT_PCRE2_32 = false,
        .SUPPORT_UNICODE = true,

        .PCRE2_EXPORT = null,
        .PCRE2_LINK_SIZE = 2,
        .PCRE2_HEAP_LIMIT = 20000000,
        .PCRE2_MATCH_LIMIT = 10000000,
        .PCRE2_MATCH_LIMIT_DEPTH = "MATCH_LIMIT",
        .PCRE2_MAX_VARLOOKBEHIND = 255,
        .NEWLINE_DEFAULT = 2,
        .PCRE2_PARENS_NEST_LIMIT = 250,
        .PCRE2GREP_BUFSIZE = 20480,
        .PCRE2GREP_MAX_BUFSIZE = 1048576,
    });

    lib.addConfigHeader(config_header);
    lib.root_module.addCMacro("PCRE2_CODE_UNIT_WIDTH", "8");
    lib.root_module.addCMacro("PCRE2_STATIC", "");
    lib.root_module.addCMacro("HAVE_CONFIG_H", "");

    lib.addIncludePath(b.path("pcre2/src"));
    lib.addCSourceFiles(.{
        .files = &PCRE2_SOURCE_FILES,
        .flags = &.{"-std=c99"},
    });

    return lib;
}

const PCRE2_SOURCE_FILES = [_][]const u8{
    "pcre2/src/pcre2_auto_possess.c",
    "pcre2/src/pcre2_chkdint.c",
    "pcre2/src/pcre2_chartables.c",
    "pcre2/src/pcre2_compile.c",
    "pcre2/src/pcre2_compile_class.c",
    "pcre2/src/pcre2_config.c",
    "pcre2/src/pcre2_context.c",
    "pcre2/src/pcre2_convert.c",
    "pcre2/src/pcre2_dfa_match.c",
    "pcre2/src/pcre2_error.c",
    "pcre2/src/pcre2_extuni.c",
    "pcre2/src/pcre2_find_bracket.c",
    "pcre2/src/pcre2_maketables.c",
    "pcre2/src/pcre2_match.c",
    "pcre2/src/pcre2_match_data.c",
    "pcre2/src/pcre2_newline.c",
    "pcre2/src/pcre2_ord2utf.c",
    "pcre2/src/pcre2_pattern_info.c",
    "pcre2/src/pcre2_script_run.c",
    "pcre2/src/pcre2_serialize.c",
    "pcre2/src/pcre2_string_utils.c",
    "pcre2/src/pcre2_study.c",
    "pcre2/src/pcre2_substitute.c",
    "pcre2/src/pcre2_substring.c",
    "pcre2/src/pcre2_tables.c",
    "pcre2/src/pcre2_ucd.c",
    "pcre2/src/pcre2_valid_utf.c",
    "pcre2/src/pcre2_xclass.c",
};
