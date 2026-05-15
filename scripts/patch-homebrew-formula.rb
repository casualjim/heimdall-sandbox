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
      %w[heimdall-sandbox heimdall-sandbox-inner].each do |binary|
        p = "\#{bin}/\#{binary}"
        chmod "+w", p
        MachO::Tools.add_rpath(p, "@loader_path/../lib", :max_align)
        system "codesign", "--force", "--sign", "-", p
      end
    end
PATCH

# Find the closing `  end` of the install method (right before `end` of the class)
if formula.sub!(/\n(  end\nend\n)/m, "\n" + patch + "\n" + "\\1")
  File.write(path, formula)
  puts "patched #{path}"
else
  warn "could not find install method end in #{path}"
  exit 1
end
