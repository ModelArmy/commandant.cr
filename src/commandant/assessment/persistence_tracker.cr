require "json"

module Commandant
  # Signal emitted when the same risk category is attempted repeatedly
  # after a prior block or denial.
  record PersistenceSignal,
    risk_tag : RiskTag,
    attempt_count : Int32,
    session_window_seconds : Int32 do
    include JSON::Serializable
  end

  # Tracks repeated attempts at blocked risk categories within a session window.
  #
  # When an agent attempts the same risk category multiple times after being
  # blocked, this is a lightweight observable for capability tunneling patterns.
  # The signal does not block execution — it enriches the assessment payload.
  class PersistenceTracker
    SESSION_WINDOW_SECONDS = 300 # 5 minutes

    record Attempt, risk_tag : RiskTag, timestamp : Time

    @attempts : Array(Attempt)
    @window_seconds : Int32

    def initialize(@window_seconds : Int32 = SESSION_WINDOW_SECONDS)
      @attempts = [] of Attempt
    end

    # Records a denied or escalated assessment's risk tags.
    def record_blocked(risk_tags : Array(RiskTag)) : Nil
      now = Time.utc
      risk_tags.each do |tag|
        @attempts << Attempt.new(tag, now)
      end
      prune_expired
    end

    # Returns a persistence signal if any risk tag in the given set
    # has been attempted 2 or more times within the session window.
    def signal_for(risk_tags : Array(RiskTag)) : PersistenceSignal?
      prune_expired
      risk_tags.each do |tag|
        count = @attempts.count { |attempt| attempt.risk_tag == tag }
        if count >= 2
          return PersistenceSignal.new(tag, count, @window_seconds)
        end
      end
      nil
    end

    # Clears all recorded attempts.
    def reset : Nil
      @attempts.clear
    end

    private def prune_expired : Nil
      cutoff = Time.utc - @window_seconds.seconds
      @attempts.reject! { |attempt| attempt.timestamp < cutoff }
    end
  end
end
