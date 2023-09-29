use crate::{controllers, error::Error, Result};
use clap::Parser;
use rocket::fs::FileServer;
use rocket::{data::Limits, Build, Config, Rocket};
use rocket_okapi::{
    openapi_get_routes,
    rapidoc::{
        make_rapidoc, ApiConfig, ApiKeyLocation, GeneralConfig, HideShowConfig, LayoutConfig,
        RapiDocConfig, RenderStyle, Theme, UiConfig,
    },
    settings::UrlObject,
};
use std::path::Path;

/// Catchers like 500, 501, 404, etc
mod catchers;

/// Server & App Configurations
pub mod config;
mod cors;

use self::config::Settings;

#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct CliOpts {
    /// loads the server configurations
    #[clap(short = 'c', long)]
    config: String,
}

/// Parse the settings from the command line arguments
fn parse_settings_from_cli() -> Result<Settings> {
    // parse the cli options
    let cli_opts = CliOpts::parse();
    let cfg_file = &cli_opts.config;

    if cfg_file.is_empty() {
        // No config file, so start
        // with default settings
        Ok(Settings::default())
    } else {
        // Config file passed in cli, check
        // to see if config file exists
        if Path::new(cfg_file).exists() {
            // load settings from the config file or return error
            // if error in loading the given config file
            Settings::from_file(cfg_file)
        } else {
            // config file does not exist, quit app
            Err(Error::ConfigFileNotFound)
        }
    }
}

/// Initialise the Rocket Server app
pub async fn init_server() -> Result<Rocket<Build>> {
    let settings = parse_settings_from_cli()?;
    let server_settings = settings.server;

    let limits = Limits::new()
        .limit("forms", server_settings.forms_limit.into())
        .limit("json", server_settings.json_limit.into());

    let rocket_cfg = Config::figment()
        .merge(("address", server_settings.host.to_string()))
        .merge(("port", server_settings.port as u16))
        .merge(("limits", limits))
        .merge(("secret_key", (server_settings.secret_key.as_str())))
        .merge(("keep_alive", server_settings.keep_alive as u32));

    // Configure SSL status for the api server
    let rocket_cfg = if let Some(ssl_cfg) = settings.ssl {
        if ssl_cfg.enabled {
            // ssl is enabled
            if ssl_cfg.pem_certificate.is_some() && ssl_cfg.pem_private_key.is_some() {
                // merge the certs & key into rocket config
                rocket_cfg
                    .merge(("tls.certs", ssl_cfg.pem_certificate))
                    .merge(("tls.key", ssl_cfg.pem_private_key))
            } else {
                // ssl certificate info not available
                return Err(Error::SslCertificateError);
            }
        } else {
            // ssl not enabled
            rocket_cfg
        }
    } else {
        // no ssl configuration
        rocket_cfg
    };

    // Configure the Rocket server with configured settings
    let app = rocket::custom(rocket_cfg).attach(cors::Cors);

    // Catchers
    let app = app.register(
        "/",
        rocket::catchers![
            catchers::bad_request,
            catchers::forbidden,
            catchers::not_authorized,
            catchers::not_found,
            catchers::unprocessed_entity,
            catchers::internal_server_error,
            catchers::too_many_requests,
        ],
    );

    // Add the doc
    let app = app.mount(
        "/docs/",
        make_rapidoc(&RapiDocConfig {
            general: GeneralConfig {
                spec_urls: vec![UrlObject::new("Api Specs", "../openapi.json")],
                ..Default::default()
            },
            hide_show: HideShowConfig {
                allow_spec_url_load: false,
                allow_spec_file_load: false,
                allow_search: true,
                allow_authentication: false,
                allow_try: true,
                show_header: false,
                ..Default::default()
            },
            ui: UiConfig {
                theme: Theme::Light,
                ..Default::default()
            },
            layout: LayoutConfig {
                render_style: RenderStyle::Read,
                ..Default::default()
            },
            api: ApiConfig {
                api_key_name: "x-api-key".to_string(),
                api_key_location: ApiKeyLocation::Header,
                api_key_value: "x-api-key".to_string(),
                ..Default::default()
            },
            ..Default::default()
        }),
    );

    // Add the index route
    let app = app.mount(
        "/",
        openapi_get_routes![
            // Index
            // controllers::index::home,
            // The implemented backends
            controllers::implemented_backends,
            // Convert endpoints
            controllers::converter::single_convert,
            // Batch Convert endpoints
            controllers::converter::batch_convert,
            // All Options
            controllers::all_options
        ],
    );
    // Mount the static files.
    let app = app.mount("/", FileServer::from(server_settings.static_folder));

    // Return the configured Rocket App
    Ok(app)
}
