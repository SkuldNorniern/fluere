//! Reading and writing Fluere's config in the Tavra text format.
//!
//! Tavra has no serde integration, so the mapping between its value model and
//! [`Config`] is written out here. The shape matches the TOML one field for
//! field, so the same config can be expressed in either format:
//!
//! ```tavra
//! plugins = {
//!     "SkuldNorniern/fluere-plugin-example" = {
//!         enabled = true
//!         path = "/opt/fluere/plugins/example"
//!         extra_arguments = {
//!             out = "/var/log/example.log"
//!         }
//!     }
//! }
//! ```

use std::collections::HashMap;

use tavra::{Map, Value};

use crate::error::ConfigError;
use crate::types::{Config, Plugin, Plugins};

/// Parse a Tavra document into a [`Config`].
pub fn from_str(input: &str) -> Result<Config, ConfigError> {
    let document =
        tavra::text::parse(input).map_err(|error| ConfigError::Tavra(error.to_string()))?;

    let root = document
        .as_map()
        .ok_or_else(|| ConfigError::Shape("the document root must be a map".to_string()))?;

    let plugins = match root.get("plugins") {
        Some(value) => parse_plugins(value)?,
        None => Plugins::new(),
    };

    Ok(Config { plugins })
}

/// Render a [`Config`] as a Tavra document.
pub fn to_string(config: &Config) -> String {
    let mut plugins = Map::new();
    for (name, plugin) in &config.plugins {
        plugins.insert(name.clone(), plugin_to_value(plugin));
    }

    let mut root = Map::new();
    root.insert("plugins".to_string(), Value::Map(plugins));

    tavra::text::format(&root)
}

fn parse_plugins(value: &Value) -> Result<Plugins, ConfigError> {
    let entries = value
        .as_map()
        .ok_or_else(|| shape("plugins", "a map", value))?;

    let mut plugins = Plugins::new();
    for (name, entry) in entries {
        plugins.insert(name.clone(), parse_plugin(name, entry)?);
    }
    Ok(plugins)
}

fn parse_plugin(name: &str, value: &Value) -> Result<Plugin, ConfigError> {
    let fields = value.as_map().ok_or_else(|| shape(name, "a map", value))?;

    // An entry that does not say otherwise is disabled, matching Plugin::default.
    let enabled = match fields.get("enabled") {
        Some(value) => value
            .as_bool()
            .ok_or_else(|| shape(&format!("{name}.enabled"), "a bool", value))?,
        None => false,
    };

    let path = match fields.get("path") {
        Some(Value::Null) | None => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| shape(&format!("{name}.path"), "a string", value))?
                .to_string(),
        ),
    };

    let extra_arguments = match fields.get("extra_arguments") {
        Some(Value::Null) | None => None,
        Some(value) => Some(parse_arguments(name, value)?),
    };

    Ok(Plugin {
        enabled,
        path,
        extra_arguments,
    })
}

fn parse_arguments(name: &str, value: &Value) -> Result<HashMap<String, String>, ConfigError> {
    let entries = value
        .as_map()
        .ok_or_else(|| shape(&format!("{name}.extra_arguments"), "a map", value))?;

    let mut arguments = HashMap::with_capacity(entries.len());
    for (key, argument) in entries {
        let argument = argument.as_str().ok_or_else(|| {
            shape(
                &format!("{name}.extra_arguments.{key}"),
                "a string",
                argument,
            )
        })?;
        arguments.insert(key.clone(), argument.to_string());
    }
    Ok(arguments)
}

fn plugin_to_value(plugin: &Plugin) -> Value {
    let mut fields = Map::new();
    fields.insert("enabled".to_string(), Value::Bool(plugin.enabled));

    if let Some(path) = plugin.path.as_ref() {
        fields.insert("path".to_string(), Value::String(path.clone()));
    }

    if let Some(arguments) = plugin.extra_arguments.as_ref() {
        let mut table = Map::new();
        for (key, value) in arguments {
            table.insert(key.clone(), Value::String(value.clone()));
        }
        fields.insert("extra_arguments".to_string(), Value::Map(table));
    }

    Value::Map(fields)
}

fn shape(field: &str, expected: &str, found: &Value) -> ConfigError {
    ConfigError::Shape(format!(
        "`{}` should be {}, found {}",
        field,
        expected,
        found.type_name()
    ))
}

#[cfg(test)]
mod tests {
    use super::{from_str, to_string};
    use crate::error::ConfigError;
    use crate::types::{Config, Plugin};
    use std::collections::HashMap;

    const SAMPLE: &str = r#"
plugins = {
    "SkuldNorniern/fluere-plugin-example" = {
        enabled = true
        path = "/opt/fluere/plugins/example"
        extra_arguments = {
            out = "/var/log/example.log"
            level = "debug"
        }
    }

    "disabled/plugin" = {
        enabled = false
    }
}
"#;

    #[test]
    fn parses_a_full_plugin_entry() {
        let config = from_str(SAMPLE).expect("sample parses");

        assert_eq!(config.plugins.len(), 2);

        let plugin = config
            .plugins
            .get("SkuldNorniern/fluere-plugin-example")
            .expect("named plugin present");
        assert!(plugin.enabled);
        assert_eq!(plugin.path.as_deref(), Some("/opt/fluere/plugins/example"));

        let arguments = plugin.extra_arguments.as_ref().expect("arguments present");
        assert_eq!(
            arguments.get("out").map(String::as_str),
            Some("/var/log/example.log")
        );
        assert_eq!(arguments.get("level").map(String::as_str), Some("debug"));
    }

    #[test]
    fn omitted_fields_become_none() {
        let config = from_str(SAMPLE).expect("sample parses");
        let plugin = config.plugins.get("disabled/plugin").expect("present");

        assert!(!plugin.enabled);
        assert!(plugin.path.is_none());
        assert!(plugin.extra_arguments.is_none());
    }

    #[test]
    fn a_document_without_plugins_is_an_empty_config() {
        let config = from_str("").expect("an empty document is valid");
        assert!(config.plugins.is_empty());
    }

    #[test]
    fn round_trips_through_the_text_format() {
        let mut arguments = HashMap::new();
        arguments.insert("out".to_string(), "/tmp/out.log".to_string());

        let mut original = Config::default();
        original.plugins.insert(
            "owner/with-slash".to_string(),
            Plugin {
                enabled: true,
                path: Some("/plugins/here".to_string()),
                extra_arguments: Some(arguments),
            },
        );
        original.plugins.insert(
            "bare".to_string(),
            Plugin {
                enabled: false,
                path: None,
                extra_arguments: None,
            },
        );

        let rendered = to_string(&original);
        let parsed = from_str(&rendered).expect("rendered config parses back");

        assert_eq!(parsed.plugins.len(), original.plugins.len());
        for (name, plugin) in &original.plugins {
            let other = parsed.plugins.get(name).expect("plugin survives the trip");
            assert_eq!(other.enabled, plugin.enabled);
            assert_eq!(other.path, plugin.path);
            assert_eq!(other.extra_arguments, plugin.extra_arguments);
        }
    }

    #[test]
    fn a_wrongly_typed_field_is_reported_not_ignored() {
        let error = from_str("plugins = { broken = { enabled = \"yes\" } }")
            .expect_err("a string is not a bool");

        match error {
            ConfigError::Shape(message) => {
                assert!(message.contains("broken.enabled"), "{}", message);
                assert!(message.contains("bool"), "{}", message);
            }
            other => panic!("expected a shape error, got {other:?}"),
        }
    }

    #[test]
    fn a_syntax_error_is_reported_as_a_tavra_error() {
        let error = from_str("plugins = {{{").expect_err("not valid tavra");
        assert!(matches!(error, ConfigError::Tavra(_)), "{error:?}");
    }
}
