//! Classic White Eclipse Workbench Light (default) & Dark OLED design system tokens for egui.

use egui::{Color32, Rounding, Stroke, Style, Visuals};

use crate::core::models::ThemeMode;

#[derive(Debug, Clone, Copy)]
pub struct ThemePalette {
    pub frame_bg: Color32,
    pub panel_bg: Color32,
    pub header_bg: Color32,
    pub surface_alt: Color32,
    pub border: Color32,
    pub border_strong: Color32,
    pub accent: Color32,
    pub selection_bg: Color32,
    pub ink: Color32,
    pub muted: Color32,
    pub ok_fg: Color32,
    pub ok_bg: Color32,
    pub warn_fg: Color32,
    pub warn_bg: Color32,
    pub err_fg: Color32,
    pub err_bg: Color32,
    pub crimson_cta: Color32,
    pub plot_bg: Color32,
    pub plot_grid: Color32,
    pub cursor_a: Color32,
    pub cursor_b: Color32,
}

pub const ECLIPSE_LIGHT: ThemePalette = ThemePalette {
    frame_bg: Color32::from_rgb(0xF3, 0xF4, 0xF6),
    panel_bg: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    header_bg: Color32::from_rgb(0xE5, 0xE7, 0xEB),
    surface_alt: Color32::from_rgb(0xF9, 0xFA, 0xFB),
    border: Color32::from_rgb(0xD1, 0xD5, 0xDB),
    border_strong: Color32::from_rgb(0x9C, 0xA3, 0xAF),
    accent: Color32::from_rgb(0x00, 0x66, 0xCC),
    selection_bg: Color32::from_rgb(0xD6, 0xE4, 0xF5),
    ink: Color32::from_rgb(0x0F, 0x17, 0x2A),
    muted: Color32::from_rgb(0x47, 0x55, 0x69),
    ok_fg: Color32::from_rgb(0x0E, 0x7C, 0x3A),
    ok_bg: Color32::from_rgb(0xDC, 0xFC, 0xE7),
    warn_fg: Color32::from_rgb(0xB4, 0x53, 0x09),
    warn_bg: Color32::from_rgb(0xFE, 0xF3, 0xC7),
    err_fg: Color32::from_rgb(0x99, 0x1B, 0x1B),
    err_bg: Color32::from_rgb(0xFE, 0xE2, 0xE2),
    crimson_cta: Color32::from_rgb(0xC8, 0x1E, 0x1E),
    plot_bg: Color32::from_rgb(0xFF, 0xFF, 0xFF),
    plot_grid: Color32::from_rgb(0xE2, 0xE8, 0xF0),
    cursor_a: Color32::from_rgb(0x00, 0x55, 0xD4),
    cursor_b: Color32::from_rgb(0xC8, 0x1E, 0x1E),
};

pub const DARK_OLED: ThemePalette = ThemePalette {
    frame_bg: Color32::from_rgb(0x14, 0x16, 0x1B),
    panel_bg: Color32::from_rgb(0x1B, 0x1E, 0x26),
    header_bg: Color32::from_rgb(0x23, 0x27, 0x32),
    surface_alt: Color32::from_rgb(0x1F, 0x23, 0x2C),
    border: Color32::from_rgb(0x33, 0x3A, 0x47),
    border_strong: Color32::from_rgb(0x4B, 0x55, 0x63),
    accent: Color32::from_rgb(0x38, 0xBD, 0xF8),
    selection_bg: Color32::from_rgb(0x1E, 0x3A, 0x5F),
    ink: Color32::from_rgb(0xF1, 0xF5, 0xF9),
    muted: Color32::from_rgb(0x94, 0xA3, 0xB8),
    ok_fg: Color32::from_rgb(0x4A, 0xDE, 0x80),
    ok_bg: Color32::from_rgb(0x06, 0x4E, 0x3B),
    warn_fg: Color32::from_rgb(0xFB, 0xBF, 0x24),
    warn_bg: Color32::from_rgb(0x45, 0x1A, 0x03),
    err_fg: Color32::from_rgb(0xF8, 0x71, 0x71),
    err_bg: Color32::from_rgb(0x45, 0x0A, 0x0A),
    crimson_cta: Color32::from_rgb(0xDC, 0x26, 0x26),
    plot_bg: Color32::from_rgb(0x0D, 0x11, 0x17),
    plot_grid: Color32::from_rgb(0x26, 0x2E, 0x3D),
    cursor_a: Color32::from_rgb(0x38, 0xBD, 0xF8),
    cursor_b: Color32::from_rgb(0xF8, 0x71, 0x71),
};

pub const LIGHT_TRACE_PALETTE: [Color32; 8] = [
    Color32::from_rgb(0x00, 0x55, 0xD4), // Cobalt Blue
    Color32::from_rgb(0xC8, 0x1E, 0x1E), // Crimson Red
    Color32::from_rgb(0x0E, 0x7C, 0x3A), // Forest Green
    Color32::from_rgb(0xB4, 0x53, 0x09), // Deep Amber
    Color32::from_rgb(0x6D, 0x28, 0xD9), // Royal Purple
    Color32::from_rgb(0x0F, 0x76, 0x6E), // Deep Teal
    Color32::from_rgb(0xA2, 0x1C, 0xAF), // Magenta
    Color32::from_rgb(0x1E, 0x29, 0x3B), // Slate Charcoal
];

pub const DARK_TRACE_PALETTE: [Color32; 8] = [
    Color32::from_rgb(0x38, 0xBD, 0xF8),
    Color32::from_rgb(0xFB, 0x71, 0x85),
    Color32::from_rgb(0x4A, 0xDE, 0x80),
    Color32::from_rgb(0xFB, 0xBF, 0x24),
    Color32::from_rgb(0xC0, 0x84, 0xFC),
    Color32::from_rgb(0x2D, 0xD4, 0xBF),
    Color32::from_rgb(0xF4, 0x72, 0xB6),
    Color32::from_rgb(0xE2, 0xE8, 0xF0),
];

pub fn palette_for(mode: ThemeMode) -> ThemePalette {
    match mode {
        ThemeMode::ClassicEclipseLight => ECLIPSE_LIGHT,
        ThemeMode::DarkOled => DARK_OLED,
    }
}

pub fn trace_color_for(idx: usize, mode: ThemeMode) -> Color32 {
    match mode {
        ThemeMode::ClassicEclipseLight => LIGHT_TRACE_PALETTE[idx % LIGHT_TRACE_PALETTE.len()],
        ThemeMode::DarkOled => DARK_TRACE_PALETTE[idx % DARK_TRACE_PALETTE.len()],
    }
}

pub fn apply_theme(ctx: &egui::Context, mode: ThemeMode, scale_pct: u32) {
    let p = palette_for(mode);
    let mut visuals = match mode {
        ThemeMode::ClassicEclipseLight => Visuals::light(),
        ThemeMode::DarkOled => Visuals::dark(),
    };
    visuals.window_fill = p.panel_bg;
    visuals.panel_fill = p.frame_bg;
    visuals.faint_bg_color = p.surface_alt;
    visuals.extreme_bg_color = p.panel_bg;
    visuals.code_bg_color = p.surface_alt;
    visuals.override_text_color = Some(p.ink);
    visuals.selection.bg_fill = p.selection_bg;
    visuals.selection.stroke = Stroke::new(1.0_f32, p.accent);
    visuals.hyperlink_color = p.accent;
    visuals.window_stroke = Stroke::new(1.0_f32, p.border_strong);
    visuals.window_rounding = Rounding::same(3.0);

    // Classic Eclipse crisp rectangular widgets (2px radius, 1px hairline border)
    let r = Rounding::same(2.0);
    visuals.widgets.noninteractive.bg_fill = p.frame_bg;
    visuals.widgets.noninteractive.weak_bg_fill = p.header_bg;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0_f32, p.ink);
    visuals.widgets.noninteractive.rounding = r;

    visuals.widgets.inactive.bg_fill = p.panel_bg;
    visuals.widgets.inactive.weak_bg_fill = p.panel_bg;
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0_f32, p.border);
    visuals.widgets.inactive.fg_stroke = Stroke::new(1.0_f32, p.ink);
    visuals.widgets.inactive.rounding = r;

    visuals.widgets.hovered.bg_fill = p.selection_bg;
    visuals.widgets.hovered.weak_bg_fill = p.selection_bg;
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0_f32, p.accent);
    visuals.widgets.hovered.fg_stroke = Stroke::new(1.0_f32, p.ink);
    visuals.widgets.hovered.rounding = r;

    visuals.widgets.active.bg_fill = p.selection_bg;
    visuals.widgets.active.weak_bg_fill = p.selection_bg;
    visuals.widgets.active.bg_stroke = Stroke::new(1.5_f32, p.accent);
    visuals.widgets.active.fg_stroke = Stroke::new(1.0_f32, p.ink);
    visuals.widgets.active.rounding = r;

    visuals.widgets.open.bg_fill = p.header_bg;
    visuals.widgets.open.weak_bg_fill = p.header_bg;
    visuals.widgets.open.bg_stroke = Stroke::new(1.0_f32, p.accent);
    visuals.widgets.open.rounding = r;

    let mut style = Style {
        visuals,
        ..Default::default()
    };
    style.spacing.item_spacing = egui::vec2(5.0, 4.0);
    style.spacing.button_padding = egui::vec2(7.0, 3.0);
    style.spacing.window_margin = egui::Margin::same(6.0);
    style.spacing.indent = 14.0;
    ctx.set_style(style);

    let zoom = (scale_pct.clamp(85, 140) as f32) / 100.0;
    ctx.set_pixels_per_point(zoom);
}
