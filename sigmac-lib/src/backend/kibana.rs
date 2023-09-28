use crate::backend::{BackEnd, QueryBuilder};
use crate::prelude::rule::sigma::SigmaRule;
use serde_json::json;

#[derive(Clone, Debug, Default)]
pub struct KibanaSavedSearchBackend;

impl BackEnd for KibanaSavedSearchBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        let columns: Vec<String> = vec![];
        let kibana = json!({
            "id": sigma_rule.id,
            "type": "search",
            "attributes": {
                "title": format!("SIGMA - {}", sigma_rule.title),
                "description": sigma_rule.description,
                "hits": 0,
                "columns": columns,
                "sort": ["@timestamp", "desc"],
                "version": 1,
                "kibanaSavedObjectMeta": {
                    "searchSourceJSON": json!({
                        "index": "winlogbeat-*",
                        "filter":  [],
                        "highlight": {
                            "pre_tags": ["@kibana-highlighted-field@"],
                            "post_tags": ["@/kibana-highlighted-field@"],
                            "fields": {"*": {}},
                            "require_field_match": false,
                            "fragment_size": 2147483647
                        },
                        "query": {
                            "query_string": {
                                "query": self.build_query(&sigma_rule),
                                "analyze_wildcard": true
                            }
                        }
                    })
                }
            },
            "references": [
                {
                    "id": "winlogbeat-*",
                    "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                    "type": "index-pattern"
                }
            ]
        });
        serde_json::to_string_pretty(&kibana).unwrap()
    }
}

impl QueryBuilder for KibanaSavedSearchBackend {
    fn build_query(&self, _rule: &SigmaRule) -> String {
        String::new()
    }
}
