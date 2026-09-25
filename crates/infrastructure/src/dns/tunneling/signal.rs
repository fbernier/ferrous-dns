/// Weighted sum of the detection signals that fired, remembering the heaviest
/// one (first wins on ties) for the alert log.
pub(crate) struct SignalScore {
    pub(crate) confidence: f32,
    top_weight: f32,
    pub(crate) top_signal: &'static str,
    pub(crate) top_measured: f32,
    pub(crate) top_threshold: f32,
}

impl SignalScore {
    pub(crate) fn new() -> Self {
        Self {
            confidence: 0.0,
            top_weight: 0.0,
            top_signal: "none",
            top_measured: 0.0,
            top_threshold: 0.0,
        }
    }

    pub(crate) fn add(&mut self, weight: f32, name: &'static str, measured: f32, threshold: f32) {
        self.confidence += weight;
        if weight > self.top_weight {
            self.top_weight = weight;
            self.top_signal = name;
            self.top_measured = measured;
            self.top_threshold = threshold;
        }
    }
}
