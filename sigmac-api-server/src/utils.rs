use std::collections::HashMap;

/// Split a given text/lines of text into key:value where
/// key is looked up to be replaced with value
pub fn load_as_field_mappings(txt: &str) -> HashMap<String, String> {
    txt.trim()
        .lines()
        .map(|s| s.split_at(s.find(':').unwrap()))
        .map(|(key, val)| {
            (
                key.trim(),
                val[1..].split(',').map(|s| s.trim()).collect::<Vec<_>>(),
            )
        })
        .collect::<HashMap<&str, Vec<&str>>>()
        .iter()
        .flat_map(|(key, val)| {
            val.iter()
                .map(|v| (*v, *key))
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<HashMap<String, String>>()
        })
        .collect()
}
