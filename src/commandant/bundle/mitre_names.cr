require "json"

module Commandant
  # Parsed representation of `mitre_names.json` from a ruleset bundle.
  #
  # Maps MITRE ATT&CK technique IDs to their metadata. Only techniques
  # referenced by the bundle's rulesets are included — this is not a
  # complete ATT&CK catalogue.
  #
  # All lookups are safe — a missing ID returns nil rather than raising.
  # Callers should always handle the nil case, as not all rulesets are
  # fully backfilled and not all technique IDs may be present.
  class MitreNames
    # A single technique entry. Structured as an object to allow future
    # addition of fields (tactic, url, description) without breaking callers.
    class Entry
      include JSON::Serializable

      getter name : String
    end

    @entries : Hash(String, Entry)

    def self.from_json(json : String) : self
      instance = new
      instance.load(json)
      instance
    end

    def initialize
      @entries = {} of String => Entry
    end

    # Returns the human-readable name for a technique ID, or nil if not found.
    #
    # ```
    # mitre_names.name_for("T1565.001") # => "Stored Data Manipulation"
    # mitre_names.name_for("T9999")     # => nil
    # ```
    def name_for(id : String) : String?
      @entries[id]?.try(&.name)
    end

    # Returns the full Entry for a technique ID, or nil if not found.
    def entry_for(id : String) : Entry?
      @entries[id]?
    end

    # Returns true if the given technique ID is present in this mapping.
    def includes?(id : String) : Bool
      @entries.has_key?(id)
    end

    # Returns the number of techniques in this mapping.
    def size : Int32
      @entries.size
    end

    # :nodoc:
    def load(json : String) : Nil
      @entries = Hash(String, Entry).from_json(json)
    end
  end
end
