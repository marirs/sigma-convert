use crate::backend::{BackEnd, QueryBuilder};
use crate::sigma::components::rule::sigma::SigmaRule;
use crate::sigma::components::rule::SiemRule;
use crate::sigma::utilities::types::LogString;
use serde_json::json;

#[derive(Clone, Debug, Default)]
pub struct HumioAlertBackend;

impl BackEnd for HumioAlertBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        let description = format!("{} {} License: https://github.com/Neo23x0/sigma/blob/master/LICENSE.Detection.Rules.md. Reference: https://tdm.socprime.com/tdm/info/.",
                                  sigma_rule.description.as_ref().unwrap_or(&LogString::from("")),
                                  if let Some(author ) = sigma_rule.author.as_ref() { format!("Author: {}.", author) } else { String::new() }
        );
        let query = json!({
            "queryString": self.build_query(&sigma_rule),
            "isLive": true,
            "start": "1h"
        });
        let humio = json!({
            "name": sigma_rule.title,
            "query": query,
            "description": description.trim(),
            "throttleTimeMillis": 60000,
            "silenced": false
        });
        serde_json::to_string_pretty(&humio).unwrap()
    }
}

impl QueryBuilder for HumioAlertBackend {
    fn build_query(&self, rule: &SigmaRule) -> String {
        let query_str = String::new();
        let siem_rule: SiemRule = rule.clone().into();
        println!("{:#?}", siem_rule);
        for _subrules in siem_rule.subrules.as_ref().into_iter() {
            // for conditions in subrules.
        }

        query_str.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::humio_alert::HumioAlertBackend;
    use crate::backend::BackEnd;
    use crate::parse_sigma_rule;
    use std::env::current_dir;

    #[test]
    pub fn convert_rule_to_humio_alert() {
        let _7zip_rule_path = current_dir()
            .unwrap()
            .join("data")
            .join("7zip_sigma_rule.yml")
            .display()
            .to_string();
        let rule = parse_sigma_rule(_7zip_rule_path.as_str()).unwrap();
        let humio_alert_backend = HumioAlertBackend::default();
        let humio_alert = humio_alert_backend.convert_rule(rule);
        println!("{}", humio_alert);
    }
}
