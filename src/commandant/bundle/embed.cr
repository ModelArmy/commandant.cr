module Commandant
  # Embeds a ruleset bundle ZIP into the binary at compile time.
  #
  # Both the bundle and its optional checksum sidecar are read via `read_file`
  # at compile time — no file I/O occurs at runtime. Checksum verification
  # semantics are identical to the path-based constructor: if a checksum is
  # provided and verification fails, a `RulesetBundle::ChecksumMismatchError`
  # is raised at startup.
  #
  # Usage:
  # ```
  # # Without checksum (RulesetVerification::None)
  # BUNDLE = Commandant.embed_bundle("vendor/commandant-rules-v0.1.1.zip")
  #
  # # With checksum sidecar (RulesetVerification::Bundle)
  # BUNDLE = Commandant.embed_bundle(
  #   "vendor/commandant-rules-v0.1.1.zip",
  #   "vendor/commandant-rules-v0.1.1.zip.sha256"
  # )
  #
  # assessor = Commandant::Assessor.from_bundle(
  #   bundle: BUNDLE,
  #   sandbox_root: Path["/workspace"],
  #   allowed_tools: %w[grep find sed cat ls]
  # )
  # ```
  macro embed_bundle(bundle_path, checksum_path = nil)
    Commandant::RulesetBundle.new(
      data: {{ read_file(bundle_path) }}.to_slice,
      checksum: {% if checksum_path != nil %}{{ read_file(checksum_path) }}{% else %}nil{% end %}
    )
  end
end
