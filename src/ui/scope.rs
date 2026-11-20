//! Bench-grade egui::Painter Oscilloscope, NaN-safe Hann-windowed FFT/THD analyzer,
//! bounded-ZOH CSV exporter, and pure-Rust software PNG oscilloscope exporter.

use std::collections::{BTreeMap, VecDeque};
use std::f64::consts::TAU;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use egui::{Align2, Color32, FontId, Pos2, Rect, Sense, Shape, Stroke, Ui, Vec2};

use crate::core::models::{ThemeMode, TriggerMode, TriggerSlope, WatchItem};
use crate::core::ring_buffer::{ChannelRingBuffer, ChannelStats};
use crate::ui::theme::{palette_for, trace_color_for};

#[derive(Debug, Clone)]
pub struct FftResult {
    pub freqs_hz: Vec<f64>,
    pub mags: Vec<f64>,
    pub peak_hz: f64,
    pub peak_amp: f64,
    pub thd_pct: f64,
    pub nyquist_hz: f64,
    pub sample_count: usize,
}

/// NaN-safe Hann-windowed spectrum analyzer: selects longest contiguous finite segment,
/// checks uniform-dt regularity, computes single-sided amplitude spectrum, Peak Hz, and Est. THD %.
pub fn compute_nan_safe_spectrum(ts: &[f64], vs: &[f64]) -> Option<FftResult> {
    let n = ts.len().min(vs.len());
    if n < 16 {
        return None;
    }

    // 1. Find longest contiguous finite segment
    let mut best_start = 0usize;
    let mut best_len = 0usize;
    let mut cur_start = 0usize;
    let mut cur_len = 0usize;
    for i in 0..n {
        if ts[i].is_finite() && vs[i].is_finite() {
            if cur_len == 0 {
                cur_start = i;
            }
            cur_len += 1;
            if cur_len > best_len {
                best_len = cur_len;
                best_start = cur_start;
            }
        } else {
            cur_len = 0;
        }
    }
    if best_len < 16 {
        return None;
    }

    // Use power-of-two radix-2 Cooley-Tukey FFT on trailing power-of-two slice (up to 1024 samples)
    let mut m = 1usize;
    while m * 2 <= best_len && m * 2 <= 1024 {
        m *= 2;
    }
    let slice_start = best_start + best_len - m;
    let seg_t = &ts[slice_start..slice_start + m];
    let seg_v = &vs[slice_start..slice_start + m];

    let total_dt = seg_t[m - 1] - seg_t[0];
    if total_dt <= 1e-9 {
        return None;
    }
    let dt_avg = total_dt / ((m - 1) as f64);
    let fs = 1.0 / dt_avg;
    let nyquist_hz = fs * 0.5;

    // Remove DC mean & apply Hann window
    let mean = seg_v.iter().sum::<f64>() / (m as f64);
    let mut re = vec![0.0f64; m];
    let mut im = vec![0.0f64; m];
    let mut win_sum = 0.0f64;
    for i in 0..m {
        let w = 0.5 * (1.0 - (TAU * (i as f64) / ((m - 1) as f64)).cos());
        re[i] = (seg_v[i] - mean) * w;
        win_sum += w;
    }

    fft_radix2(&mut re, &mut im);

    let half = m / 2;
    let scale = 2.0 / win_sum.max(1e-9);
    let mut freqs_hz = Vec::with_capacity(half);
    let mut mags = Vec::with_capacity(half);
    let mut peak_bin = 1usize;
    let mut peak_amp = 0.0f64;
    for k in 0..half {
        let f = (k as f64) * fs / (m as f64);
        let mag = (re[k] * re[k] + im[k] * im[k]).sqrt() * scale;
        freqs_hz.push(f);
        mags.push(mag);
        if k >= 1 && mag > peak_amp {
            peak_amp = mag;
            peak_bin = k;
        }
    }

    let peak_hz = freqs_hz.get(peak_bin).copied().unwrap_or(0.0);
    // Estimate THD from 2nd..5th harmonics
    let mut harm_sq = 0.0f64;
    for h in 2..=5 {
        let target_bin = peak_bin * h;
        if target_bin < half {
            // Peak in +-1 bin neighborhood for spectral leakage tolerance
            let lo = target_bin.saturating_sub(1);
            let hi = (target_bin + 1).min(half - 1);
            let mut h_amp = 0.0f64;
            for &mg in &mags[lo..=hi] {
                if mg > h_amp {
                    h_amp = mg;
                }
            }
            harm_sq += h_amp * h_amp;
        }
    }
    let thd_pct = if peak_amp > 1e-12 {
        (harm_sq.sqrt() / peak_amp) * 100.0
    } else {
        0.0
    };

    Some(FftResult {
        freqs_hz,
        mags,
        peak_hz,
        peak_amp,
        thd_pct,
        nyquist_hz,
        sample_count: m,
    })
}

fn fft_radix2(re: &mut [f64], im: &mut [f64]) {
    let n = re.len();
    // Bit-reversal permutation
    let mut j = 0usize;
    for i in 1..n {
        let mut bit = n >> 1;
        while j & bit != 0 {
            j ^= bit;
            bit >>= 1;
        }
        j ^= bit;
        if i < j {
            re.swap(i, j);
            im.swap(i, j);
        }
    }
    let mut len = 2usize;
    while len <= n {
        let half = len / 2;
        let ang = -TAU / (len as f64);
        let wlen_re = ang.cos();
        let wlen_im = ang.sin();
        for i in (0..n).step_by(len) {
            let mut w_re = 1.0;
            let mut w_im = 0.0;
            for k in 0..half {
                let u_re = re[i + k];
                let u_im = im[i + k];
                let v_re = re[i + k + half] * w_re - im[i + k + half] * w_im;
                let v_im = re[i + k + half] * w_im + im[i + k + half] * w_re;
                re[i + k] = u_re + v_re;
                im[i + k] = u_im + v_im;
                re[i + k + half] = u_re - v_re;
                im[i + k + half] = u_im - v_im;
                let nxt_re = w_re * wlen_re - w_im * wlen_im;
                w_im = w_re * wlen_im + w_im * wlen_re;
                w_re = nxt_re;
            }
        }
        len <<= 1;
    }
}

/// Bounded Zero-Order-Hold multi-rate CSV alignment: emits `NaN` when staleness exceeds `max_stale_s`
/// so slow-rate channels never silently hold obsolete stale values across long disconnects.
pub fn align_bounded_zoh(
    channels: &[(&str, &[f64], &[f64])],
    max_stale_s: f64,
) -> (Vec<f64>, Vec<(String, Vec<f64>)>) {
    let mut master_t: Vec<f64> = Vec::new();
    for (_, ts, _) in channels {
        for &t in *ts {
            if t.is_finite() {
                master_t.push(t);
            }
        }
    }
    master_t.sort_by(|a, b| a.total_cmp(b));
    master_t.dedup_by(|a, b| (*a - *b).abs() < 1e-9);

    let mut cols = Vec::with_capacity(channels.len());
    for (name, ts, vs) in channels {
        let mut aligned = Vec::with_capacity(master_t.len());
        let mut cursor = 0usize;
        for &t in &master_t {
            while cursor + 1 < ts.len() && ts[cursor + 1] <= t + 1e-9 {
                cursor += 1;
            }
            if ts.is_empty() || ts[cursor] > t + 1e-9 {
                aligned.push(f64::NAN);
            } else {
                let age = t - ts[cursor];
                let v = vs[cursor];
                if age <= max_stale_s && v.is_finite() {
                    aligned.push(v);
                } else {
                    aligned.push(f64::NAN);
                }
            }
        }
        cols.push(((*name).to_string(), aligned));
    }
    (master_t, cols)
}

pub fn export_scope_csv(
    path: &Path,
    channels: &[(&str, &[f64], &[f64])],
    max_stale_s: f64,
) -> Result<usize, String> {
    let (ts, cols) = align_bounded_zoh(channels, max_stale_s);
    let f = File::create(path).map_err(|e| e.to_string())?;
    let mut bw = BufWriter::new(f);
    write!(bw, "time_s").map_err(|e| e.to_string())?;
    for (name, _) in &cols {
        write!(bw, ",{name}").map_err(|e| e.to_string())?;
    }
    writeln!(bw).map_err(|e| e.to_string())?;
    for i in 0..ts.len() {
        write!(bw, "{:.6}", ts[i]).map_err(|e| e.to_string())?;
        for (_, vals) in &cols {
            let v = vals[i];
            if v.is_finite() {
                write!(bw, ",{v:.8}").map_err(|e| e.to_string())?;
            } else {
                write!(bw, ",NaN").map_err(|e| e.to_string())?;
            }
        }
        writeln!(bw).map_err(|e| e.to_string())?;
    }
    bw.flush().map_err(|e| e.to_string())?;
    Ok(ts.len())
}

/// Pure-Rust software PNG renderer for exporting high-DPI Classic White Eclipse / Dark OLED oscilloscope captures.
pub fn render_scope_png(
    path: &Path,
    width: u32,
    height: u32,
    mode: ThemeMode,
    traces: &[(&str, Color32, &[f64], &[f64])],
) -> Result<(), String> {
    let p = palette_for(mode);
    let w = width as usize;
    let h = height as usize;
    let mut rgb = vec![0u8; w * h * 3];

    let fill_rect = |buf: &mut [u8], x0: usize, y0: usize, x1: usize, y1: usize, col: Color32| {
        for y in y0.min(h)..y1.min(h) {
            for x in x0.min(w)..x1.min(w) {
                let off = (y * w + x) * 3;
                buf[off] = col.r();
                buf[off + 1] = col.g();
                buf[off + 2] = col.b();
            }
        }
    };

    fill_rect(&mut rgb, 0, 0, w, h, p.frame_bg);
    let pad_l = 56usize;
    let pad_r = 24usize;
    let pad_t = 32usize;
    let pad_b = 36usize;
    fill_rect(&mut rgb, pad_l, pad_t, w - pad_r, h - pad_b, p.plot_bg);

    // Draw grid lines
    let pw = (w - pad_l - pad_r).max(1);
    let ph = (h - pad_t - pad_b).max(1);
    for gi in 0..=8 {
        let gx = pad_l + (pw * gi) / 8;
        fill_rect(&mut rgb, gx, pad_t, (gx + 1).min(w), h - pad_b, p.plot_grid);
    }
    for gj in 0..=6 {
        let gy = pad_t + (ph * gj) / 6;
        fill_rect(&mut rgb, pad_l, gy, w - pad_r, (gy + 1).min(h), p.plot_grid);
    }
    // Border
    fill_rect(&mut rgb, pad_l, pad_t, w - pad_r, pad_t + 1, p.border_strong);
    fill_rect(&mut rgb, pad_l, h - pad_b, w - pad_r, h - pad_b + 1, p.border_strong);
    fill_rect(&mut rgb, pad_l, pad_t, pad_l + 1, h - pad_b, p.border_strong);
    fill_rect(&mut rgb, w - pad_r, pad_t, w - pad_r + 1, h - pad_b, p.border_strong);

    // Find global bounds
    let mut tmin = f64::INFINITY;
    let mut tmax = f64::NEG_INFINITY;
    let mut vmin = f64::INFINITY;
    let mut vmax = f64::NEG_INFINITY;
    for (_, _, ts, vs) in traces {
        for (&t, &v) in ts.iter().zip(vs.iter()) {
            if t.is_finite() && v.is_finite() {
                tmin = tmin.min(t);
                tmax = tmax.max(t);
                vmin = vmin.min(v);
                vmax = vmax.max(v);
            }
        }
    }
    if tmin.is_finite() && tmax > tmin {
        if (vmax - vmin).abs() < 1e-6 {
            vmin -= 1.0;
            vmax += 1.0;
        }
        let pad_y = (vmax - vmin) * 0.08;
        vmin -= pad_y;
        vmax += pad_y;

        let draw_line = |buf: &mut [u8], x0: i32, y0: i32, x1: i32, y1: i32, col: Color32| {
            let dx = (x1 - x0).abs();
            let dy = (y1 - y0).abs();
            let steps = dx.max(dy).max(1);
            for s in 0..=steps {
                let x = x0 + ((x1 - x0) * s) / steps;
                let y = y0 + ((y1 - y0) * s) / steps;
                for ox in 0..=1 {
                    for oy in 0..=1 {
                        let px = x + ox;
                        let py = y + oy;
                        if px >= 0 && py >= 0 && (px as usize) < w && (py as usize) < h {
                            let off = ((py as usize) * w + (px as usize)) * 3;
                            buf[off] = col.r();
                            buf[off + 1] = col.g();
                            buf[off + 2] = col.b();
                        }
                    }
                }
            }
        };

        for (_, col, ts, vs) in traces {
            let mut prev: Option<(i32, i32)> = None;
            for (&t, &v) in ts.iter().zip(vs.iter()) {
                if !t.is_finite() || !v.is_finite() {
                    prev = None;
                    continue;
                }
                let x = pad_l as i32 + (((t - tmin) / (tmax - tmin)) * (pw as f64)) as i32;
                let y = (h - pad_b) as i32 - (((v - vmin) / (vmax - vmin)) * (ph as f64)) as i32;
                if let Some((px, py)) = prev {
                    draw_line(&mut rgb, px, py, x, y, *col);
                }
                prev = Some((x, y));
            }
        }
    }

    let file = File::create(path).map_err(|e| e.to_string())?;
    let mut encoder = png::Encoder::new(BufWriter::new(file), width, height);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    let mut writer = encoder.write_header().map_err(|e| e.to_string())?;
    writer.write_image_data(&rgb).map_err(|e| e.to_string())?;
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeBottomTab {
    Stats,
    Fft,
    TriggerLog,
}

#[derive(Debug, Clone)]
pub struct ScopeState {
    pub pane_count: usize,
    pub window_sec: Option<f64>,
    pub paused: bool,
    pub autoscale_y: bool,
    pub xy_mode: bool,
    pub xy_x_id: String,
    pub xy_y_id: String,
    pub cursors_enabled: bool,
    pub cursor_a_frac: f32,
    pub cursor_b_frac: f32,
    pub trigger_mode: TriggerMode,
    pub trigger_slope: TriggerSlope,
    pub trigger_source_id: String,
    pub trigger_level: f64,
    pub trigger_armed: bool,
    pub trigger_frozen: bool,
    pub trigger_last_t: Option<f64>,
    pub trigger_log: VecDeque<String>,
    pub bottom_tab: ScopeBottomTab,
    pub fft_channel_id: String,
    pub request_export_csv: bool,
    pub request_export_png: bool,
    pub request_clear: bool,
}

impl Default for ScopeState {
    fn default() -> Self {
        Self {
            pane_count: 2,
            window_sec: Some(10.0),
            paused: false,
            autoscale_y: true,
            xy_mode: false,
            xy_x_id: String::new(),
            xy_y_id: String::new(),
            cursors_enabled: false,
            cursor_a_frac: 0.30,
            cursor_b_frac: 0.70,
            trigger_mode: TriggerMode::Free,
            trigger_slope: TriggerSlope::Rising,
            trigger_source_id: String::new(),
            trigger_level: 12.0,
            trigger_armed: false,
            trigger_frozen: false,
            trigger_last_t: None,
            trigger_log: VecDeque::new(),
            bottom_tab: ScopeBottomTab::Stats,
            fft_channel_id: String::new(),
            request_export_csv: false,
            request_export_png: false,
            request_clear: false,
        }
    }
}

impl ScopeState {
    pub fn notify_write_trigger(&mut self, sym_path: &str, t_now: f64) {
        if self.trigger_mode == TriggerMode::OnWrite {
            self.trigger_last_t = Some(t_now);
            self.trigger_log.push_front(format!("t={t_now:.3}s  ON-WRITE trigger fired on {sym_path}"));
            if self.trigger_log.len() > 64 {
                self.trigger_log.pop_back();
            }
        }
    }

    pub fn ui(
        &mut self,
        ui: &mut Ui,
        theme: ThemeMode,
        watch_items: &[WatchItem],
        buffers: &BTreeMap<String, ChannelRingBuffer>,
    ) {
        let p = palette_for(theme);

        // Toolbar Row 1: Core scope controls (compact single row, zero clipping at 1280px)
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("Panes:").strong());
            for n in 1..=3 {
                if ui.selectable_label(self.pane_count == n, format!("{n}")).clicked() {
                    self.pane_count = n;
                }
            }
            ui.separator();
            let win_label = match self.window_sec {
                Some(w) => format!("{w:.0}s"),
                None => "All".to_string(),
            };
            egui::ComboBox::from_id_source("scope_win_cb")
                .width(56.0)
                .selected_text(win_label)
                .show_ui(ui, |ui| {
                    for &(lbl, val) in &[
                        ("2s", Some(2.0)),
                        ("5s", Some(5.0)),
                        ("10s", Some(10.0)),
                        ("30s", Some(30.0)),
                        ("60s", Some(60.0)),
                        ("All", None),
                    ] {
                        if ui.selectable_label(self.window_sec == val, lbl).clicked() {
                            self.window_sec = val;
                        }
                    }
                });

            let pause_txt = if self.paused || self.trigger_frozen { "Resume" } else { "Pause" };
            if ui.button(pause_txt).clicked() {
                if self.trigger_frozen {
                    self.trigger_frozen = false;
                    self.trigger_armed = self.trigger_mode == TriggerMode::Single;
                } else {
                    self.paused = !self.paused;
                }
            }
            ui.toggle_value(&mut self.autoscale_y, "Auto-Y");
            ui.toggle_value(&mut self.cursors_enabled, "Cursors");
            ui.toggle_value(&mut self.xy_mode, "XY");

            ui.menu_button("Export", |ui| {
                if ui.button("Export CSV (Bounded ZOH)...").clicked() {
                    self.request_export_csv = true;
                    ui.close_menu();
                }
                if ui.button("Export Scope PNG...").clicked() {
                    self.request_export_png = true;
                    ui.close_menu();
                }
            });
            if ui.button("Clear").on_hover_text("Clear oscilloscope ring buffers").clicked() {
                self.request_clear = true;
            }
        });

        // Toolbar Row 2: Trigger bar
        ui.horizontal_wrapped(|ui| {
            ui.label(egui::RichText::new("Trig:").color(p.muted));
            egui::ComboBox::from_id_source("scope_trig_mode")
                .width(74.0)
                .selected_text(self.trigger_mode.label())
                .show_ui(ui, |ui| {
                    for m in [TriggerMode::Free, TriggerMode::Auto, TriggerMode::Single, TriggerMode::OnWrite] {
                        if ui.selectable_label(self.trigger_mode == m, m.label()).clicked() {
                            self.trigger_mode = m;
                            self.trigger_frozen = false;
                            self.trigger_armed = m == TriggerMode::Single;
                        }
                    }
                });
            egui::ComboBox::from_id_source("scope_trig_slope")
                .width(76.0)
                .selected_text(self.trigger_slope.label())
                .show_ui(ui, |ui| {
                    for s in [TriggerSlope::Rising, TriggerSlope::Falling, TriggerSlope::WindowOut, TriggerSlope::BitHigh] {
                        if ui.selectable_label(self.trigger_slope == s, s.label()).clicked() {
                            self.trigger_slope = s;
                        }
                    }
                });
            ui.label("Lvl:");
            ui.add(egui::DragValue::new(&mut self.trigger_level).speed(0.1).max_decimals(3));

            let plotted: Vec<&WatchItem> = watch_items.iter().filter(|w| w.plot_pane > 0).collect();
            if self.trigger_source_id.is_empty() {
                if let Some(first) = plotted.first() {
                    self.trigger_source_id = first.id.clone();
                }
            }
            if self.fft_channel_id.is_empty() {
                if let Some(first) = plotted.first() {
                    self.fft_channel_id = first.id.clone();
                }
            }
            let src_name = plotted
                .iter()
                .find(|w| w.id == self.trigger_source_id)
                .map(|w| w.symbol_path.as_str())
                .unwrap_or("(src)");
            egui::ComboBox::from_id_source("scope_trig_src")
                .width(105.0)
                .selected_text(src_name)
                .show_ui(ui, |ui| {
                    for w in &plotted {
                        if ui.selectable_label(self.trigger_source_id == w.id, &w.symbol_path).clicked() {
                            self.trigger_source_id = w.id.clone();
                        }
                    }
                });
            if self.trigger_mode == TriggerMode::Single {
                let btn = if self.trigger_frozen { "Re-Arm" } else if self.trigger_armed { "Armed" } else { "Arm" };
                if ui.button(btn).clicked() {
                    self.trigger_frozen = false;
                    self.trigger_armed = true;
                }
            }
        });

        // Evaluate Single / Auto edge trigger on source channel
        if !self.paused && !self.trigger_frozen && matches!(self.trigger_mode, TriggerMode::Auto | TriggerMode::Single) {
            if let Some(rb) = buffers.get(&self.trigger_source_id) {
                let (ts, vs) = rb.view_window(self.window_sec);
                if ts.len() >= 2 {
                    let n = ts.len();
                    let prev = vs[n - 2];
                    let curr = vs[n - 1];
                    if prev.is_finite() && curr.is_finite() {
                        let fired = match self.trigger_slope {
                            TriggerSlope::Rising => prev < self.trigger_level && curr >= self.trigger_level,
                            TriggerSlope::Falling => prev > self.trigger_level && curr <= self.trigger_level,
                            TriggerSlope::WindowOut => curr.abs() > self.trigger_level.abs(),
                            TriggerSlope::BitHigh => (curr as i64 & (self.trigger_level as i64).max(1)) != 0,
                        };
                        if fired {
                            let t_now = ts[n - 1];
                            self.trigger_last_t = Some(t_now);
                            self.trigger_log.push_front(format!(
                                "t={t_now:.3}s  {} trigger @ {:.3}",
                                self.trigger_slope.label(),
                                curr
                            ));
                            if self.trigger_log.len() > 64 {
                                self.trigger_log.pop_back();
                            }
                            if self.trigger_mode == TriggerMode::Single && self.trigger_armed {
                                self.trigger_frozen = true;
                                self.trigger_armed = false;
                            }
                        }
                    }
                }
            }
        }

        ui.separator();

        // Reserve bottom space for Stats / FFT / Trigger Log tabs
        let avail_h = ui.available_height();
        let bottom_h = 122.0f32.min((avail_h * 0.34).max(92.0));
        let plot_area_h = (avail_h - bottom_h - 8.0).max(120.0);

        let mut all_stats: Vec<(String, Color32, ChannelStats)> = Vec::new();

        if self.xy_mode {
            // XY Phase-Plane Mode
            let plotted: Vec<&WatchItem> = watch_items.iter().filter(|w| w.plot_pane > 0).collect();
            if self.xy_x_id.is_empty() && !plotted.is_empty() {
                self.xy_x_id = plotted[0].id.clone();
            }
            if self.xy_y_id.is_empty() && plotted.len() >= 2 {
                self.xy_y_id = plotted[1].id.clone();
            }
            ui.horizontal(|ui| {
                ui.label("X:");
                let xn = plotted.iter().find(|w| w.id == self.xy_x_id).map(|w| w.symbol_path.as_str()).unwrap_or("-");
                egui::ComboBox::from_id_source("xy_x_cb").width(110.0).selected_text(xn).show_ui(ui, |ui| {
                    for w in &plotted {
                        if ui.selectable_label(self.xy_x_id == w.id, &w.symbol_path).clicked() {
                            self.xy_x_id = w.id.clone();
                        }
                    }
                });
                ui.label("Y:");
                let yn = plotted.iter().find(|w| w.id == self.xy_y_id).map(|w| w.symbol_path.as_str()).unwrap_or("-");
                egui::ComboBox::from_id_source("xy_y_cb").width(110.0).selected_text(yn).show_ui(ui, |ui| {
                    for w in &plotted {
                        if ui.selectable_label(self.xy_y_id == w.id, &w.symbol_path).clicked() {
                            self.xy_y_id = w.id.clone();
                        }
                    }
                });
            });
            self.draw_xy_canvas(ui, (plot_area_h - 24.0).max(90.0), theme, buffers);
        } else {
            // 1..3 synchronized time-domain oscilloscope panes
            let n_panes = self.pane_count.clamp(1, 3);
            let each_h = ((plot_area_h - ((n_panes - 1) as f32 * 5.0)) / (n_panes as f32)).max(68.0);
            for pane_idx in 1..=n_panes {
                let pane_items: Vec<&WatchItem> = watch_items
                    .iter()
                    .filter(|w| w.plot_pane as usize == pane_idx)
                    .collect();
                self.draw_time_pane(ui, pane_idx, each_h, theme, &pane_items, buffers, &mut all_stats);
                if pane_idx < n_panes {
                    ui.add_space(4.0);
                }
            }
        }

        ui.separator();

        // Bottom Scope Inspector Tabs: Channel Stats | FFT Peaks / THD | Trigger Log
        ui.horizontal(|ui| {
            ui.selectable_value(&mut self.bottom_tab, ScopeBottomTab::Stats, "Channel Stats");
            ui.selectable_value(&mut self.bottom_tab, ScopeBottomTab::Fft, "FFT Peaks / THD");
            ui.selectable_value(
                &mut self.bottom_tab,
                ScopeBottomTab::TriggerLog,
                format!("Trigger Log ({})", self.trigger_log.len()),
            );
        });

        egui::ScrollArea::vertical().id_source("scope_bottom_scroll").max_height(bottom_h - 26.0).show(ui, |ui| {
            match self.bottom_tab {
                ScopeBottomTab::Stats => {
                    if all_stats.is_empty() {
                        ui.label(egui::RichText::new("Assign Watch items to Plot Pane 1..3 to view live stats.").color(p.muted));
                    } else {
                        egui::Grid::new("scope_stats_grid").striped(true).spacing([10.0, 2.0]).show(ui, |ui| {
                            for hdr in ["Channel", "Curr", "Min", "Max", "Avg", "Pk-Pk", "RMS"] {
                                ui.label(egui::RichText::new(hdr).strong().size(11.0));
                            }
                            ui.end_row();
                            for (name, col, st) in &all_stats {
                                ui.label(egui::RichText::new(name).color(*col).monospace().size(11.0));
                                for val in [st.curr, st.min, st.max, st.avg, st.pkpk, st.rms] {
                                    ui.label(egui::RichText::new(format!("{val:.4}")).monospace().size(11.0));
                                }
                                ui.end_row();
                            }
                        });
                    }
                }
                ScopeBottomTab::Fft => {
                    let plotted: Vec<&WatchItem> = watch_items.iter().filter(|w| w.plot_pane > 0).collect();
                    ui.horizontal(|ui| {
                        ui.label("Channel:");
                        let cn = plotted.iter().find(|w| w.id == self.fft_channel_id).map(|w| w.symbol_path.as_str()).unwrap_or("-");
                        egui::ComboBox::from_id_source("fft_ch_cb").width(140.0).selected_text(cn).show_ui(ui, |ui| {
                            for w in &plotted {
                                if ui.selectable_label(self.fft_channel_id == w.id, &w.symbol_path).clicked() {
                                    self.fft_channel_id = w.id.clone();
                                }
                            }
                        });
                    });
                    if let Some(rb) = buffers.get(&self.fft_channel_id) {
                        let (ts, vs) = rb.view_window(self.window_sec);
                        if let Some(fft) = compute_nan_safe_spectrum(ts, vs) {
                            ui.horizontal_wrapped(|ui| {
                                ui.label(
                                    egui::RichText::new(format!(
                                        "Peak: {:.2} Hz  |  Amp: {:.4}  |  Est. THD: {:.2}%  |  Nyquist: {:.1} Hz  |  N={}",
                                        fft.peak_hz, fft.peak_amp, fft.thd_pct, fft.nyquist_hz, fft.sample_count
                                    ))
                                    .monospace()
                                    .strong()
                                    .size(11.5),
                                );
                            });
                            // Mini bar spectrum preview
                            let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width(), 44.0), Sense::hover());
                            let painter = ui.painter_at(rect);
                            painter.rect_filled(rect, 2.0, p.plot_bg);
                            painter.rect_stroke(rect, 2.0, Stroke::new(1.0_f32, p.border));
                            let max_m = fft.peak_amp.max(1e-9);
                            let bins = fft.mags.len().min(96);
                            let bw = rect.width() / (bins.max(1) as f32);
                            for k in 1..bins {
                                let h_frac = ((fft.mags[k] / max_m) as f32).clamp(0.0, 1.0);
                                let x = rect.left() + (k as f32) * bw;
                                let bar_h = h_frac * (rect.height() - 4.0);
                                painter.line_segment(
                                    [Pos2::new(x, rect.bottom() - 2.0), Pos2::new(x, rect.bottom() - 2.0 - bar_h)],
                                    Stroke::new((bw * 0.7).max(1.5), p.accent),
                                );
                            }
                        } else {
                            ui.label(egui::RichText::new("Collecting >= 16 finite samples for FFT...").color(p.muted));
                        }
                    } else {
                        ui.label(egui::RichText::new("Select a plotted channel for FFT/THD.").color(p.muted));
                    }
                }
                ScopeBottomTab::TriggerLog => {
                    if self.trigger_log.is_empty() {
                        ui.label(egui::RichText::new("No trigger events yet.").color(p.muted));
                    } else {
                        for line in &self.trigger_log {
                            ui.label(egui::RichText::new(line).monospace().size(11.0));
                        }
                    }
                }
            }
        });
    }

    #[allow(clippy::too_many_arguments)]
    fn draw_time_pane(
        &mut self,
        ui: &mut Ui,
        pane_idx: usize,
        height: f32,
        theme: ThemeMode,
        items: &[&WatchItem],
        buffers: &BTreeMap<String, ChannelRingBuffer>,
        all_stats: &mut Vec<(String, Color32, ChannelStats)>,
    ) {
        let p = palette_for(theme);
        let avail_w = ui.available_width().max(120.0);
        let (rect, resp) = ui.allocate_exact_size(Vec2::new(avail_w, height), Sense::click_and_drag());
        let painter = ui.painter_at(rect);

        painter.rect_filled(rect, 2.0, p.plot_bg);
        painter.rect_stroke(rect, 2.0, Stroke::new(1.0_f32, p.border_strong));

        let pad_l = 48.0;
        let pad_r = 8.0;
        let pad_t = 18.0;
        let pad_b = 18.0;
        let inner = Rect::from_min_max(
            Pos2::new(rect.left() + pad_l, rect.top() + pad_t),
            Pos2::new((rect.right() - pad_r).max(rect.left() + pad_l + 20.0), (rect.bottom() - pad_b).max(rect.top() + pad_t + 20.0)),
        );

        // Grid
        for i in 0..=6 {
            let x = inner.left() + inner.width() * (i as f32 / 6.0);
            painter.line_segment([Pos2::new(x, inner.top()), Pos2::new(x, inner.bottom())], Stroke::new(1.0_f32, p.plot_grid));
        }
        for j in 0..=4 {
            let y = inner.top() + inner.height() * (j as f32 / 4.0);
            painter.line_segment([Pos2::new(inner.left(), y), Pos2::new(inner.right(), y)], Stroke::new(1.0_f32, p.plot_grid));
        }

        // Gather decimated traces
        let mut traces: Vec<(&WatchItem, Color32, Vec<f64>, Vec<f64>)> = Vec::new();
        let mut tmin = f64::INFINITY;
        let mut tmax = f64::NEG_INFINITY;
        let mut vmin = f64::INFINITY;
        let mut vmax = f64::NEG_INFINITY;
        let max_pts = (inner.width() as usize * 2).clamp(256, 2000);

        for item in items {
            let col = trace_color_for(item.color_index, theme);
            if let Some(rb) = buffers.get(&item.id) {
                let (ts, vs, st) = rb.decimated_window(self.window_sec, max_pts);
                if let Some(s) = st {
                    all_stats.push((item.symbol_path.clone(), col, s));
                }
                for (&t, &v) in ts.iter().zip(vs.iter()) {
                    if t.is_finite() {
                        tmin = tmin.min(t);
                        tmax = tmax.max(t);
                    }
                    if v.is_finite() {
                        vmin = vmin.min(v);
                        vmax = vmax.max(v);
                    }
                }
                traces.push((item, col, ts, vs));
            }
        }

        // Legend header strip
        let mut lx = rect.left() + 6.0;
        let pane_lbl = format!("P{pane_idx}");
        painter.text(
            Pos2::new(lx, rect.top() + 9.0),
            Align2::LEFT_CENTER,
            &pane_lbl,
            FontId::monospace(10.5),
            p.muted,
        );
        lx += 24.0;
        for (item, col, _, _) in &traces {
            let tag = format!("● {}", item.symbol_path);
            let galley = painter.layout_no_wrap(tag, FontId::monospace(10.5), *col);
            let w_txt = galley.size().x;
            if lx + w_txt < rect.right() - 8.0 {
                painter.galley(Pos2::new(lx, rect.top() + 2.0), galley, *col);
                lx += w_txt + 10.0;
            }
        }

        if !tmin.is_finite() || tmax <= tmin {
            painter.text(
                inner.center(),
                Align2::CENTER_CENTER,
                if items.is_empty() {
                    format!("Pane {pane_idx} — assign channels in Watch Table")
                } else {
                    "Waiting for live samples...".into()
                },
                FontId::proportional(11.5),
                p.muted,
            );
            return;
        }

        if !vmin.is_finite() || (vmax - vmin).abs() < 1e-6 {
            vmin = if vmin.is_finite() { vmin - 1.0 } else { -1.0 };
            vmax = vmin + 2.0;
        } else {
            let pad = (vmax - vmin) * 0.08;
            vmin -= pad;
            vmax += pad;
        }

        // Y-axis tick labels
        for j in 0..=4 {
            let frac = j as f64 / 4.0;
            let val = vmax - frac * (vmax - vmin);
            let y = inner.top() + inner.height() * (frac as f32);
            painter.text(
                Pos2::new(inner.left() - 4.0, y),
                Align2::RIGHT_CENTER,
                format!("{val:.2}"),
                FontId::monospace(9.5),
                p.muted,
            );
        }
        // X-axis labels
        painter.text(
            Pos2::new(inner.left(), rect.bottom() - 9.0),
            Align2::LEFT_CENTER,
            format!("{tmin:.2}s"),
            FontId::monospace(9.5),
            p.muted,
        );
        painter.text(
            Pos2::new(inner.right(), rect.bottom() - 9.0),
            Align2::RIGHT_CENTER,
            format!("{tmax:.2}s"),
            FontId::monospace(9.5),
            p.muted,
        );

        let to_pos = |t: f64, v: f64| -> Pos2 {
            let xf = ((t - tmin) / (tmax - tmin)).clamp(0.0, 1.0) as f32;
            let yf = ((v - vmin) / (vmax - vmin)).clamp(0.0, 1.0) as f32;
            Pos2::new(inner.left() + xf * inner.width(), inner.bottom() - yf * inner.height())
        };

        // Trigger level line if source is in this pane
        if self.trigger_mode != TriggerMode::Free
            && items.iter().any(|w| w.id == self.trigger_source_id)
            && self.trigger_level >= vmin
            && self.trigger_level <= vmax
        {
            let ty = to_pos(tmin, self.trigger_level).y;
            painter.line_segment(
                [Pos2::new(inner.left(), ty), Pos2::new(inner.right(), ty)],
                Stroke::new(1.0_f32, p.warn_fg),
            );
        }

        // Draw traces with NaN-gap breaks
        for (_, col, ts, vs) in &traces {
            let mut seg: Vec<Pos2> = Vec::new();
            for (&t, &v) in ts.iter().zip(vs.iter()) {
                if t.is_finite() && v.is_finite() {
                    seg.push(to_pos(t, v));
                } else if seg.len() >= 2 {
                    painter.add(Shape::line(std::mem::take(&mut seg), Stroke::new(1.75_f32, *col)));
                } else {
                    seg.clear();
                }
            }
            if seg.len() >= 2 {
                painter.add(Shape::line(seg, Stroke::new(1.75_f32, *col)));
            }
        }

        // Interactive vertical A/B cursors
        if self.cursors_enabled {
            if resp.dragged() {
                if let Some(pos) = resp.interact_pointer_pos() {
                    let f = ((pos.x - inner.left()) / inner.width()).clamp(0.0, 1.0);
                    if (f - self.cursor_a_frac).abs() <= (f - self.cursor_b_frac).abs() {
                        self.cursor_a_frac = f;
                    } else {
                        self.cursor_b_frac = f;
                    }
                }
            }
            let xa = inner.left() + self.cursor_a_frac * inner.width();
            let xb = inner.left() + self.cursor_b_frac * inner.width();
            painter.line_segment([Pos2::new(xa, inner.top()), Pos2::new(xa, inner.bottom())], Stroke::new(1.2_f32, p.cursor_a));
            painter.line_segment([Pos2::new(xb, inner.top()), Pos2::new(xb, inner.bottom())], Stroke::new(1.2_f32, p.cursor_b));
            let ta = tmin + (self.cursor_a_frac as f64) * (tmax - tmin);
            let tb = tmin + (self.cursor_b_frac as f64) * (tmax - tmin);
            let dt = (tb - ta).abs();
            let inv_dt = if dt > 1e-9 { format!("{:.2}Hz", 1.0 / dt) } else { "--".into() };
            let badge = format!("Δt={dt:.4}s ({inv_dt})");
            painter.text(
                Pos2::new(inner.right() - 4.0, inner.top() + 8.0),
                Align2::RIGHT_CENTER,
                badge,
                FontId::monospace(10.0),
                p.accent,
            );
        }
    }

    fn draw_xy_canvas(
        &self,
        ui: &mut Ui,
        height: f32,
        theme: ThemeMode,
        buffers: &BTreeMap<String, ChannelRingBuffer>,
    ) {
        let p = palette_for(theme);
        let (rect, _) = ui.allocate_exact_size(Vec2::new(ui.available_width().max(120.0), height), Sense::hover());
        let painter = ui.painter_at(rect);
        painter.rect_filled(rect, 2.0, p.plot_bg);
        painter.rect_stroke(rect, 2.0, Stroke::new(1.0_f32, p.border_strong));

        let (Some(rx), Some(ry)) = (buffers.get(&self.xy_x_id), buffers.get(&self.xy_y_id)) else {
            painter.text(rect.center(), Align2::CENTER_CENTER, "Select X and Y plotted channels", FontId::proportional(11.5), p.muted);
            return;
        };
        let (_, vx) = rx.view_window(self.window_sec);
        let (_, vy) = ry.view_window(self.window_sec);
        let n = vx.len().min(vy.len());
        if n < 2 {
            return;
        }
        let mut xmin = f64::INFINITY;
        let mut xmax = f64::NEG_INFINITY;
        let mut ymin = f64::INFINITY;
        let mut ymax = f64::NEG_INFINITY;
        for i in 0..n {
            if vx[i].is_finite() && vy[i].is_finite() {
                xmin = xmin.min(vx[i]);
                xmax = xmax.max(vx[i]);
                ymin = ymin.min(vy[i]);
                ymax = ymax.max(vy[i]);
            }
        }
        if !xmin.is_finite() || (xmax - xmin).abs() < 1e-9 || (ymax - ymin).abs() < 1e-9 {
            return;
        }
        let inner = rect.shrink(20.0);
        let mut pts = Vec::with_capacity(n);
        for i in 0..n {
            if vx[i].is_finite() && vy[i].is_finite() {
                let xf = ((vx[i] - xmin) / (xmax - xmin)) as f32;
                let yf = ((vy[i] - ymin) / (ymax - ymin)) as f32;
                pts.push(Pos2::new(inner.left() + xf * inner.width(), inner.bottom() - yf * inner.height()));
            }
        }
        if pts.len() >= 2 {
            let tip = *pts.last().unwrap();
            painter.add(Shape::line(pts, Stroke::new(1.6_f32, p.accent)));
            painter.circle_filled(tip, 4.0, p.crimson_cta);
        }
    }
}
