module Commandant
  # Describes the level of checksum verification performed on a ruleset bundle.
  #
  # This value is carried through to `AssessmentResponse#ruleset_verification`
  # so consumers can distinguish trust levels between assessments.
  #
  # - `None`    — no bundle was used (directory-based loader), or no checksum
  #               was provided. Verification was not performed.
  # - `Bundle`  — the ZIP-level SHA256 was verified against a provided checksum.
  #               The bundle was not modified after release.
  # - `Entries` — per-entry checksums from the manifest were verified.
  #               Each individual ruleset file matches the packaged manifest.
  # - `Full`    — both ZIP-level and per-entry verification passed.
  enum RulesetVerification
    None
    Bundle
    Entries
    Full
  end
end
