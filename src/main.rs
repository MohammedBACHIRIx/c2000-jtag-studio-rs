#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use c2000_jtag_studio::ui::app_ui::C2000StudioApp;

fn main() -> eframe::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let auto_sim = args.iter().any(|a| a == "--sim");

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("C2000 JTAG Studio v2 — Native Rust Edition (Classic White Eclipse)")
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1200.0, 680.0]),
        ..Default::default()
    };

    eframe::run_native(
        "C2000 JTAG Studio v2",
        native_options,
        Box::new(move |cc| Ok(Box::new(C2000StudioApp::new(cc, auto_sim)))),
    )
}
