const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("coapz", .{
        .root_source_file = b.path("src/root.zig"),
    });

    { // Static library
        const lib = b.addStaticLibrary(.{
            .name = "coapz",
            .root_source_file = b.path("src/root.zig"),
            .target = target,
            .optimize = optimize,
        });

        b.installArtifact(lib);
    }

    { // Tests
        const tests = b.addTest(.{
            .target = target,
            .optimize = optimize,
            .root_source_file = b.path("src/root.zig"),
        });

        const test_cmd = b.addRunArtifact(tests);
        test_cmd.step.dependOn(b.getInstallStep());
        const test_step = b.step("test", "Run tests");
        test_step.dependOn(&test_cmd.step);
    }
}
