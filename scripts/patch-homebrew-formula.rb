# Patches the dist-generated Homebrew formula to install the WebGPU Dawn
# shared library alongside the binaries and add the necessary rpath/codesign.
path = ARGV[0]
formula = File.read(path)

patch = <<~PATCH

    # Install the WebGPU Dawn shared library.
    dylib = Dir["libwebgpu_dawn.*"].first
    lib.install dylib if dylib

    # Add rpath so binaries find the shared library in Homebrew's lib directory.
    if OS.mac?
      p = "\#{bin}/heimdall-sandbox"
      chmod "+w", p
      MachO::Tools.add_rpath(p, "@loader_path/../lib", :max_align)
      system "codesign", "--force", "--sign", "-", p
    end
PATCH

# Insert BEFORE the doc_files/leftover_contents block so the dylib gets
# lib.install'd before pkgshare.install snatches it up.
if formula.sub!(/(    # Homebrew will automatically)/m, patch + "\n    \\1")
  File.write(path, formula)
  puts "patched #{path}"
else
  warn "could not find doc_files anchor in #{path}"
  exit 1
end
