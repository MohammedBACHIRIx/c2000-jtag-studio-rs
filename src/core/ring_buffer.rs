//! Zero-copy 2N mirrored ring buffer with peak-preserving min/max envelope decimation and NaN gap support.

#[derive(Debug, Clone, Copy)]
pub struct ChannelStats {
    pub curr: f64,
    pub min: f64,
    pub max: f64,
    pub avg: f64,
    pub pkpk: f64,
    pub rms: f64,
}

#[derive(Debug, Clone)]
pub struct ChannelRingBuffer {
    capacity: usize,
    times: Vec<f64>,
    values: Vec<f64>,
    write_idx: usize,
    count: usize,
    version: u64,
}

impl ChannelRingBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(16);
        Self {
            capacity: cap,
            times: vec![0.0; 2 * cap],
            values: vec![0.0; 2 * cap],
            write_idx: 0,
            count: 0,
            version: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn clear(&mut self) {
        self.write_idx = 0;
        self.count = 0;
        self.version = self.version.wrapping_add(1);
    }

    pub fn append(&mut self, t: f64, v: f64) {
        let idx = self.write_idx;
        self.times[idx] = t;
        self.times[idx + self.capacity] = t;
        self.values[idx] = v;
        self.values[idx + self.capacity] = v;
        self.write_idx = (idx + 1) % self.capacity;
        if self.count < self.capacity {
            self.count += 1;
        }
        self.version = self.version.wrapping_add(1);
    }

    pub fn append_batch(&mut self, ts: &[f64], vs: &[f64]) {
        let n = ts.len().min(vs.len());
        if n == 0 {
            return;
        }
        let start_src = n.saturating_sub(self.capacity);
        for i in start_src..n {
            let idx = self.write_idx;
            self.times[idx] = ts[i];
            self.times[idx + self.capacity] = ts[i];
            self.values[idx] = vs[i];
            self.values[idx + self.capacity] = vs[i];
            self.write_idx = (idx + 1) % self.capacity;
            if self.count < self.capacity {
                self.count += 1;
            }
        }
        self.version = self.version.wrapping_add(1);
    }

    pub fn append_nan_gap(&mut self, t: f64) {
        self.append(t, f64::NAN);
    }

    pub fn view_all(&self) -> (&[f64], &[f64]) {
        if self.count == 0 {
            return (&[], &[]);
        }
        let start = if self.count < self.capacity {
            0
        } else {
            self.write_idx
        };
        let end = start + self.count;
        (&self.times[start..end], &self.values[start..end])
    }

    pub fn view_window(&self, window_sec: Option<f64>) -> (&[f64], &[f64]) {
        let (ts, vs) = self.view_all();
        if ts.is_empty() {
            return (&[], &[]);
        }
        let Some(win) = window_sec else {
            return (ts, vs);
        };
        let t_end = *ts.last().unwrap_or(&0.0);
        let cutoff = t_end - win;
        let lo = ts.partition_point(|&t| t < cutoff);
        (&ts[lo..], &vs[lo..])
    }

    /// Peak-preserving min/max envelope decimation that keeps narrow glitches and NaN gaps intact.
    pub fn decimated_window(&self, window_sec: Option<f64>, max_points: usize) -> (Vec<f64>, Vec<f64>, Option<ChannelStats>) {
        let (ts, vs) = self.view_window(window_sec);
        if ts.is_empty() {
            return (Vec::new(), Vec::new(), None);
        }

        // Exact stats across full undecimated window
        let mut vmin = f64::INFINITY;
        let mut vmax = f64::NEG_INFINITY;
        let mut sum = 0.0;
        let mut sum_sq = 0.0;
        let mut curr = f64::NAN;
        let mut n_fin = 0usize;
        for &v in vs {
            if v.is_finite() {
                if v < vmin {
                    vmin = v;
                }
                if v > vmax {
                    vmax = v;
                }
                sum += v;
                sum_sq += v * v;
                curr = v;
                n_fin += 1;
            }
        }
        let stats = if n_fin > 0 {
            let avg = sum / (n_fin as f64);
            let rms = (sum_sq / (n_fin as f64)).sqrt();
            Some(ChannelStats {
                curr,
                min: vmin,
                max: vmax,
                avg,
                pkpk: vmax - vmin,
                rms,
            })
        } else {
            None
        };

        let cap = max_points.max(64);
        if ts.len() <= cap {
            return (ts.to_vec(), vs.to_vec(), stats);
        }

        let n_buckets = (cap / 2).max(1);
        let mut out_t = Vec::with_capacity(cap + 8);
        let mut out_v = Vec::with_capacity(cap + 8);
        let len = ts.len();

        for b in 0..n_buckets {
            let s = (b * len) / n_buckets;
            let e = (((b + 1) * len) / n_buckets).max(s + 1).min(len);
            let mut bmin = f64::INFINITY;
            let mut bmax = f64::NEG_INFINITY;
            let mut idx_min = s;
            let mut idx_max = s;
            let mut has_nan = false;
            let mut nan_idx = s;
            let mut any_fin = false;
            for (i, &v) in vs.iter().enumerate().take(e).skip(s) {
                if v.is_finite() {
                    any_fin = true;
                    if v < bmin {
                        bmin = v;
                        idx_min = i;
                    }
                    if v > bmax {
                        bmax = v;
                        idx_max = i;
                    }
                } else if !has_nan {
                    has_nan = true;
                    nan_idx = i;
                }
            }
            if !any_fin {
                out_t.push(ts[nan_idx]);
                out_v.push(f64::NAN);
            } else {
                if idx_min <= idx_max {
                    out_t.push(ts[idx_min]);
                    out_v.push(vs[idx_min]);
                    if idx_max != idx_min {
                        out_t.push(ts[idx_max]);
                        out_v.push(vs[idx_max]);
                    }
                } else {
                    out_t.push(ts[idx_max]);
                    out_v.push(vs[idx_max]);
                    out_t.push(ts[idx_min]);
                    out_v.push(vs[idx_min]);
                }
                if has_nan {
                    out_t.push(ts[nan_idx]);
                    out_v.push(f64::NAN);
                }
            }
        }
        (out_t, out_v, stats)
    }
}
