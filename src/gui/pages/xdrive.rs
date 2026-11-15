//! Shared XDRIVE presentation. All JSON conversion and mutations go through ApplicationService.
use super::HelpText;
use crate::app::{ApplicationService, XdriveEditorSide, XdriveFieldView};
use egui::{Color32, RichText, TextEdit, Ui};

const HELP: HelpText = HelpText::new(
    "XDRIVE beta v26.11.9+: use the same Xray version on both ends. VLESS Encryption is required; generate a pair with the official xray vlessenc action on Protocol, then copy its client encryption to the outbound. No flow/testpre. Clients need enabled Mux, nonnegative concurrency/xudpConcurrency and UDP443 other than skip (reverse opens its own Mux). Both ends access storage, without a direct client/server connection. For Google Drive, create the OAuth project and grant access yourself, then enter folder ID and ClientID, ClientSecret, RefreshToken in that order. Drive API quotas and polling affect latency and throughput. The explicit preset sets eagerWindowMs=10000, TLS h2 and client Mux; all other omitted values remain core defaults. h3 requires TLS ALPN exactly h3; Google Drive h3 permits only noise UDP masks and no brutal/force-brutal. No official Share URI/QR format exists yet.",
    "XDRIVE beta v26.11.9+: версии Xray с обеих сторон должны совпадать. Нужен VLESS Encryption: сгенерируйте пару официальной командой xray vlessenc на вкладке Protocol, затем скопируйте client encryption в outbound. Без flow/testpre. Клиенту нужен Mux, неотрицательные concurrency/xudpConcurrency и UDP443 не skip (reverse открывает свой Mux). Обе стороны обращаются к хранилищу, прямого соединения клиент–сервер нет. Для Google Drive самостоятельно настройте OAuth project и доступ, затем введите folder ID и ClientID, ClientSecret, RefreshToken именно в этом порядке. Квоты Drive API и polling влияют на задержку и скорость. Явный пресет задаёт eagerWindowMs=10000, TLS h2 и клиентский Mux; остальные отсутствующие значения оставлены ядру. Для h3 нужен TLS ALPN ровно h3; у Google Drive с h3 разрешена только UDP-маска noise, brutal/force-brutal запрещены. Официального формата Share URI/QR пока нет.",
);
const ADVANCED: HelpText = HelpText::new(
    "All eight numeric fields are uint32; empty = absent, explicit zero is kept and leaves the runtime default to Xray. Bytes: segmentBytes. Milliseconds: flushIntervalMs, pollIntervalMs, maxPollIntervalMs, eagerWindowMs, holeTimeoutMs. Seconds: sessionTtlSeconds. concurrency controls storage requests, not VLESS Mux. XMUX has five int32 ranges and signed hKeepAlivePeriod seconds; positive maxConnections and maxConcurrency conflict. Omitted XMUX defaults are supplied by the core. S3 uses endpoint/region/bucket/pathStyle; empty pathStyle means core default true. AccessKeyID, SecretAccessKey, optional SessionToken stay in secrets[]. Generic template JSON may contain credentials, so it is masked and Preview hides the entire template. Unknown and unsupported fields remain available in Raw JSON. Changing service never deletes its other settings or credentials.",
    "Все восемь числовых полей — uint32; пусто означает отсутствие, явный ноль сохраняется и оставляет runtime default ядру. Байты: segmentBytes. Миллисекунды: flushIntervalMs, pollIntervalMs, maxPollIntervalMs, eagerWindowMs, holeTimeoutMs. Секунды: sessionTtlSeconds. concurrency — запросы к storage, а не VLESS Mux. XMUX содержит пять диапазонов int32 и знаковый hKeepAlivePeriod в секундах; положительные maxConnections и maxConcurrency несовместимы. Отсутствующие XMUX defaults задаёт ядро. У S3 — endpoint/region/bucket/pathStyle; пустой pathStyle означает true по умолчанию. AccessKeyID, SecretAccessKey и необязательный SessionToken — в secrets[]. Произвольный template JSON может содержать credentials: он маскируется, Preview скрывает узел целиком. Неизвестные и неподдерживаемые поля доступны в Raw JSON. Смена service не удаляет остальные настройки и credentials.",
);
const TLS_HELP: HelpText = HelpText::new(
    "This inbound connects to storage as a TLS client, so no server certificate is required. TLS h2 is a useful starting point for Google Drive; for h3 enter exactly h3 in alpn. Comma-separated ALPN is passed without trimming individual values. Usually leave serverName empty so the core uses the storage endpoint. fingerprint and echConfigList apply to the storage TLS connection. Existing advanced TLS fields are preserved and can be inspected in Raw JSON. Selecting none retains inactive security blocks.",
    "Этот inbound обращается к storage как TLS-клиент, серверный сертификат не требуется. Для Google Drive можно начать с TLS h2; для h3 укажите alpn ровно h3. ALPN разделяется запятыми без обрезания пробелов внутри значений. Обычно serverName оставляют пустым, чтобы ядро использовало storage endpoint. fingerprint и echConfigList относятся к TLS-соединению с хранилищем. Существующие advanced TLS-поля сохраняются и доступны в Raw JSON. Выбор none сохраняет неактивные security-блоки.",
);

fn field(ui: &mut Ui, field: &mut XdriveFieldView, reveal: bool) -> bool {
    ui.label(&field.label);
    let old = field.text.clone();
    if field.id == "service" {
        egui::ComboBox::from_id_salt("xdrive_service")
            .selected_text(&field.text)
            .show_ui(ui, |ui| {
                for value in ["local", "google-drive", "template", "s3"] {
                    ui.selectable_value(&mut field.text, value.to_owned(), value);
                }
            });
    } else if field.id == "s3.pathStyle" || field.id == "security" {
        egui::ComboBox::from_id_salt(&field.id)
            .selected_text(if field.text.is_empty() {
                "core default"
            } else {
                &field.text
            })
            .show_ui(ui, |ui| {
                let values: &[&str] = if field.id == "security" {
                    &["none", "tls"]
                } else {
                    &["", "true", "false"]
                };
                for value in values {
                    ui.selectable_value(
                        &mut field.text,
                        (*value).to_owned(),
                        if value.is_empty() {
                            "core default"
                        } else {
                            value
                        },
                    );
                }
            });
    } else {
        ui.add(
            TextEdit::singleline(&mut field.text)
                .password(field.secret && !reveal)
                .desired_width(370.0)
                .hint_text("absent / core default"),
        );
    }
    ui.end_row();
    old != field.text
}

pub(crate) fn show(ui: &mut Ui, service: &mut ApplicationService, side: XdriveEditorSide) {
    let Some(mut view) = service.xdrive_editor_view(side) else {
        return;
    };
    ui.push_id(format!("xdrive-{side:?}-{}",view.identity),|ui|{
        ui.separator();ui.horizontal(|ui|{ui.strong("XDRIVE (streamSettings.xdriveSettings)");super::help_button(ui,"XDRIVE beta",HELP);});
        ui.label("Beta: identical Xray versions, VLESS Encryption, storage credentials; Share URI/QR unavailable.");
        if !view.editable{ui.label("This settings shape is preserved. Use Raw JSON to edit it.");return;}
        if ui.add_enabled(view.fields.iter().all(|f| f.text.is_empty()),egui::Button::new("Apply Google Drive beta preset (new settings)")).clicked(){
            let message=service.apply_xdrive_google_preset(side).unwrap_or_else(|error|error);service.show_status_message(message);
        }
        let reveal_id=ui.make_persistent_id("reveal_credentials");
        let mut reveal=ui.ctx().data_mut(|d|d.get_temp::<bool>(reveal_id).unwrap_or(false));
        ui.checkbox(&mut reveal,"Reveal credentials and template");ui.ctx().data_mut(|d|d.insert_temp(reveal_id,reveal));
        egui::Grid::new("xdrive_common_fields").num_columns(2).show(ui,|ui|{
            for item in view.fields.iter_mut().filter(|f|!f.advanced){if field(ui,item,reveal) && let Err(error)=service.set_xdrive_field(side,&item.id,item.text.clone()){service.show_status_message(error);}}
        });
        egui::CollapsingHeader::new("Advanced storage settings / XMUX / template").default_open(view.template.is_some()).show(ui,|ui|{
            super::help_button(ui,"Storage advanced",ADVANCED);
            egui::Grid::new("xdrive_advanced_fields").num_columns(2).show(ui,|ui|{
                for item in view.fields.iter_mut().filter(|f|f.advanced){if field(ui,item,reveal) && let Err(error)=service.set_xdrive_field(side,&item.id,item.text.clone()){service.show_status_message(error);}}
            });
            if let Some(template)=view.template.as_mut(){
                ui.label("template (JSON; credentials hidden in Preview)");
                if ui.add(TextEdit::multiline(template).desired_rows(8).desired_width(f32::INFINITY).password(!reveal)).changed()
                    && let Err(error)=service.set_xdrive_field(side,"template",template.clone()){service.show_status_message(error);
                }
            }
            ui.label(format!("Preserved fields without structured controls: {}. Inspect Raw JSON for all fields.",view.preserved_count));
        });
        if let Some(problem)=view.problem{ui.label(RichText::new(problem).color(Color32::from_rgb(220,80,80)));}
    });
    if side == XdriveEditorSide::Inbound {
        show_inbound_tls(ui, service);
    }
}

pub(super) fn show_inbound_tls(ui: &mut Ui, service: &mut ApplicationService) {
    let Some(mut fields) = service.inbound_xdrive_tls_fields() else {
        return;
    };
    ui.separator();
    ui.horizontal(|ui| {
        ui.strong("Storage client TLS (streamSettings.tlsSettings)");
        super::help_button(ui, "Storage client TLS", TLS_HELP);
    });
    ui.label("Client security for the storage connection; no server certificate is needed.");
    let tls = fields.first().is_some_and(|f| f.text == "tls");
    egui::Grid::new("inbound_xdrive_tls")
        .num_columns(2)
        .show(ui, |ui| {
            for item in &mut fields {
                ui.add_enabled_ui(item.id == "security" || tls, |ui| {
                    if field(ui, item, false)
                        && let Err(error) =
                            service.set_inbound_xdrive_tls_field(&item.id, item.text.clone())
                    {
                        service.show_status_message(error);
                    }
                });
            }
        });
}
