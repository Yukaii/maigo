const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard optimization options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall. Here we do not
    // set a preferred release mode, allowing the user to decide how to optimize.
    const optimize = b.standardOptimizeOption(.{});

    // Add pg.zig dependency
    const pg_dep = b.dependency("pg", .{
        .target = target,
        .optimize = optimize,
    });

    // libssh build configuration
    const libssh_build_dir = "deps/libssh/build";
    const libssh_lib_dir = b.fmt("{s}/lib", .{libssh_build_dir});
    const libssh_include_dir = "deps/libssh/include";

    // Step to build libssh if needed
    const build_libssh_step = b.step("build-libssh", "Build libssh dependency");
    const libssh_build_cmd = b.addSystemCommand(&.{ "sh", "-c", "cd deps/libssh && " ++
        "mkdir -p build && " ++
        "cd build && " ++
        "cmake .. " ++
        "-DCMAKE_BUILD_TYPE=Release " ++
        "-DWITH_EXAMPLES=OFF " ++
        "-DWITH_SERVER=ON " ++
        "-DWITH_SFTP=ON " ++
        "-DWITH_ZLIB=ON " ++
        "-DUNIT_TESTING=OFF " ++
        "-DWITH_GSSAPI=OFF " ++
        "-DBUILD_SHARED_LIBS=ON && " ++
        "make -j$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)" });
    build_libssh_step.dependOn(&libssh_build_cmd.step);

    // This creates a "module", which represents a collection of source files alongside
    // some compilation options, such as optimization mode and linked system libraries.
    // Every executable or library we compile will be based on one or more modules.
    const lib_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // We will also create a module for our other entry point, 'main.zig'.
    const exe_mod = b.createModule(.{
        // `root_source_file` is the Zig "entry point" of the module. If a module
        // only contains e.g. external object files, you can make this `null`.
        // In this case the main source file is merely a path, however, in more
        // complicated build scripts, this could be a generated file.
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    // Modules can depend on one another using the `std.Build.Module.addImport` function.
    // This is what allows Zig source code to use `@import("foo")` where 'foo' is not a
    // file path. In this case, we set up `exe_mod` to import `lib_mod`.
    exe_mod.addImport("maigo_lib", lib_mod);
    
    // Add pg module to both lib and exe modules
    lib_mod.addImport("pg", pg_dep.module("pg"));
    exe_mod.addImport("pg", pg_dep.module("pg"));

    // Now, we will create a static library based on the module we created above.
    // This creates a `std.Build.Step.Compile`, which is the build step responsible
    // for actually invoking the compiler.
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "maigo",
        .root_module = lib_mod,
    });

    // Configure library linking
    configureLibraryLinking(b, lib, libssh_include_dir, libssh_lib_dir);

    // Ensure libssh is built before compiling the library
    lib.step.dependOn(build_libssh_step);

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    // This creates another `std.Build.Step.Compile`, but this one builds an executable
    // rather than a static library.
    const exe = b.addExecutable(.{
        .name = "maigo",
        .root_module = exe_mod,
    });

    // Configure executable linking
    configureLibraryLinking(b, exe, libssh_include_dir, libssh_lib_dir);

    // Ensure libssh is built before compiling the executable
    exe.step.dependOn(build_libssh_step);

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(exe);

    // This *creates* a Run step in the build graph, to be executed when another
    // step is evaluated that depends on it. The next line below will establish
    // such a dependency.
    const run_cmd = b.addRunArtifact(exe);

    // By making the run step depend on the install step, it will be run from the
    // installation directory rather than directly from within the cache directory.
    // This is not necessary, however, if the application depends on other installed
    // files, this ensures they will be present and in the expected location.
    run_cmd.step.dependOn(b.getInstallStep());

    // This allows the user to pass arguments to the application in the build
    // command itself, like this: `zig build run -- arg1 arg2 etc`
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build run`
    // This will evaluate the `run` step rather than the default, which is "install".
    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });

    // Configure test library linking
    configureLibraryLinking(b, lib_unit_tests, libssh_include_dir, libssh_lib_dir);
    lib_unit_tests.step.dependOn(build_libssh_step);

    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);

    const exe_unit_tests = b.addTest(.{
        .root_module = exe_mod,
    });

    // Configure test executable linking
    configureLibraryLinking(b, exe_unit_tests, libssh_include_dir, libssh_lib_dir);
    exe_unit_tests.step.dependOn(build_libssh_step);

    const run_exe_unit_tests = b.addRunArtifact(exe_unit_tests);

    // Similar to creating the run step earlier, this exposes a `test` step to
    // the `zig build --help` menu, providing a way for the user to request
    // running the unit tests.
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);
    test_step.dependOn(&run_exe_unit_tests.step);

    // PostgreSQL integration test
    const postgres_test = b.addExecutable(.{
        .name = "test_postgres_integration",
        .root_source_file = b.path("test_postgres_integration.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    // Configure PostgreSQL test linking
    configureLibraryLinking(b, postgres_test, libssh_include_dir, libssh_lib_dir);
    postgres_test.root_module.addImport("pg", pg_dep.module("pg"));
    postgres_test.step.dependOn(build_libssh_step);
    
    const postgres_test_run = b.addRunArtifact(postgres_test);
    const postgres_test_step = b.step("test-postgres", "Run PostgreSQL integration test");
    postgres_test_step.dependOn(&postgres_test_run.step);

    // PostgreSQL debug test  
    const postgres_debug = b.addExecutable(.{
        .name = "debug_postgres",
        .root_source_file = b.path("debug_postgres.zig"),
        .target = target,
        .optimize = optimize,
    });
    
    configureLibraryLinking(b, postgres_debug, libssh_include_dir, libssh_lib_dir);
    postgres_debug.root_module.addImport("pg", pg_dep.module("pg"));
    postgres_debug.step.dependOn(build_libssh_step);
    
    const postgres_debug_run = b.addRunArtifact(postgres_debug);
    const postgres_debug_step = b.step("debug-postgres", "Run PostgreSQL debug test");
    postgres_debug_step.dependOn(&postgres_debug_run.step);

    // Database setup commands
    const setup_db_cmd = b.addSystemCommand(&.{ "sh", "scripts/setup_postgres.sh", "test" });
    const setup_db_step = b.step("setup-db", "Setup PostgreSQL test database");
    setup_db_step.dependOn(&setup_db_cmd.step);

    const reset_db_cmd = b.addSystemCommand(&.{ "sh", "scripts/setup_postgres.sh", "reset" });
    const reset_db_step = b.step("reset-db", "Reset PostgreSQL databases");
    reset_db_step.dependOn(&reset_db_cmd.step);

    // Custom build steps for development
    const clean_step = b.step("clean", "Clean build artifacts and libssh build");
    const clean_cmd = b.addSystemCommand(&.{ "sh", "-c", "rm -rf zig-out zig-cache deps/libssh/build" });
    clean_step.dependOn(&clean_cmd.step);

    const setup_step = b.step("setup", "Initialize submodules and build dependencies");
    const setup_cmd = b.addSystemCommand(&.{ "sh", "-c", "git submodule update --init --recursive && " ++
        "cd deps/libssh && git checkout libssh-0.11.2" });
    setup_step.dependOn(&setup_cmd.step);
    setup_step.dependOn(build_libssh_step);
}

fn configureLibraryLinking(b: *std.Build, compile_step: *std.Build.Step.Compile, libssh_include_dir: []const u8, libssh_lib_dir: []const u8) void {
    // Link C standard library
    compile_step.linkLibC();

    // Link SQLite3
    compile_step.linkSystemLibrary("sqlite3");

    // Add libssh include path and library
    compile_step.addIncludePath(b.path(libssh_include_dir));
    compile_step.addLibraryPath(b.path(libssh_lib_dir));
    compile_step.linkSystemLibrary("ssh");

    // For macOS, we might need additional system libraries
    if (compile_step.rootModuleTarget().os.tag == .macos) {
        compile_step.linkFramework("Security");
        compile_step.linkFramework("CoreFoundation");
    }
}
