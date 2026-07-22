//! Main window and eframe application integration.

use crate::app::ApplicationService;
use crate::storage::{WindowPosition, WindowSize};

use super::navigation::Page;
use super::sidebar;
use super::status_bar;

/// Desktop GUI application.
///
/// Owns the application service and hosts the egui user interface.
/// The GUI layer does not access SSH, Xray, config files, or init-system
/// internals directly — all of that goes through [`ApplicationService`].
pub struct FeldjaegerApp {
    service: ApplicationService,
    page: Page,
}

impl FeldjaegerApp {
    /// Creates a new GUI application instance using persisted preferences.
    pub fn new(service: ApplicationService) -> Self {
        let page = Page::from_label(&service.ui_config().last_page);
        Self { service, page }
    }

    /// Returns the underlying application service.
    pub fn service(&self) -> &ApplicationService {
        &self.service
    }

    fn persist_ui_preferences(&mut self, ctx: &egui::Context, sidebar_width: f32) {
        self.service.set_sidebar_width(sidebar_width);
        self.service.set_last_page(self.page.label());

        let viewport = ctx.input(|i| {
            i.viewport()
                .outer_rect
                .map(|rect| (rect.width(), rect.height(), rect.min.x, rect.min.y))
                .or_else(|| {
                    i.viewport()
                        .inner_rect
                        .map(|rect| (rect.width(), rect.height(), rect.min.x, rect.min.y))
                })
        });

        if let Some((width, height, x, y)) = viewport {
            self.service.set_window_size(WindowSize { width, height });
            self.service.set_window_position(WindowPosition { x, y });
        }
    }
}

impl eframe::App for FeldjaegerApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.service.tick_status();

        let needs_repaint = self.service.connection_test_state().is_connecting()
            || self.service.is_xray_log_following()
            || !matches!(
                self.service.status_snapshot().operation,
                crate::app::CurrentOperation::Ready
            );

        if needs_repaint {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::bottom("status_bar")
            .exact_size(status_bar::STATUS_BAR_HEIGHT)
            .resizable(false)
            .show_separator_line(true)
            .show(ui, |ui| {
                status_bar::show(ui, &self.service.status_snapshot());
            });

        let sidebar_width = self.service.ui_config().sidebar_width;
        let previous_page = self.page;
        let sidebar_response = egui::Panel::left("sidebar")
            .resizable(true)
            .default_size(sidebar_width)
            .size_range(120.0..=480.0)
            .show(ui, |ui| sidebar::show(ui, &mut self.page));

        if previous_page == Page::Logs && self.page != Page::Logs {
            self.service.leave_xray_logs_page();
        }

        egui::CentralPanel::default().show(ui, |ui| {
            self.page.show(ui, &mut self.service);
        });

        self.persist_ui_preferences(ui.ctx(), sidebar_response.response.rect.width());
    }
}

/// Runs the Feldjaeger desktop application.
pub fn run() -> eframe::Result {
    let service = ApplicationService::new();
    let ui = service.ui_config().clone();

    let mut viewport = egui::ViewportBuilder::default()
        .with_title("Feldjäger")
        .with_inner_size([ui.window_size.width, ui.window_size.height]);

    if let Some(position) = ui.window_position {
        viewport = viewport.with_position([position.x, position.y]);
    }

    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };

    eframe::run_native(
        "Feldjäger",
        options,
        Box::new(move |_cc| Ok(Box::new(FeldjaegerApp::new(service)))),
    )
}
