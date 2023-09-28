use crate::backend::{BackEnd, QueryBuilder};
use crate::prelude::rule::sigma::SigmaRule;
use crate::prelude::rule::sigma::{ConditionExpression, SigmaDetectionCondition};
use crate::prelude::SiemField;
use crate::sigma::components::rule::RuleOperator;
use crate::sigma::components::rule::SiemRule;
use crate::utils::parse_condition;
use std::process::exit;

#[derive(Clone, Debug, Default)]
pub struct SplunkBackend {}

impl BackEnd for SplunkBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        self.build_query(&sigma_rule).clone()
    }
}

impl QueryBuilder for SplunkBackend {
    fn build_query(&self, rule: &SigmaRule) -> String {
        let mut query_str = format!("index=* source=\"WinEventLog:*\" AND ");
        let siem_rule: SiemRule = rule.clone().into();
        let conditions = match parse_condition(rule.detection.condition.to_string().as_str()) {
            Ok(conds) => conds,
            Err(e) => {
                eprintln!("{:?}", e);
                exit(1);
            }
        };
        let mut condition_queries: Vec<(String, String)> = vec![];
        for (sub_rule_name, sub_rule) in siem_rule.subrules.as_ref().into_iter() {
            // for conditions in subrules.
            let mut conditions_list = vec![];
            for condition in &sub_rule.conditions {
                let mut query_str = String::new();
                let (cond_name, cond_oper) =
                    (condition.field.to_string(), condition.operator.clone());
                let regex;
                match cond_oper.clone() {
                    RuleOperator::StartsWith(mut pattern) => {
                        pattern = pattern.replace("\\", "\\\\");
                        regex = format!("{}*", pattern);
                        query_str.push_str(cond_name.as_str());
                        query_str.push_str(format!("=\"{}\"", regex).as_str());
                        // Map the condition name
                    }
                    RuleOperator::EndsWith(mut pattern) => {
                        pattern = pattern.replace("\\", "\\\\");
                        regex = format!("*{}", pattern);
                        query_str.push_str(cond_name.as_str());
                        query_str.push_str(format!("=\"{}\"", regex).as_str());
                    }
                    RuleOperator::Contains(mut pattern) => {
                        pattern = pattern.replace("\\", "\\\\");
                        regex = format!("*{}*", pattern);
                        query_str.push_str(cond_name.as_str());
                        query_str.push_str(format!("=\"{}\"", regex).as_str())
                    }
                    RuleOperator::Equals(field) => {
                        match field {
                            SiemField::Array(_) => {}
                            _ => {
                                // query_str.push('(');
                                query_str.push_str(cond_name.as_str());
                                query_str.push_str(format!("=\"{}\"", field.to_string()).as_str());
                                // query_str.push(')');
                            }
                        }
                    }
                    RuleOperator::Any(cond_list) => {
                        // let cond_name = self.get_mapping(cond_name);
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries.push(format!("{}=\"{}\"", cond_name, val));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!("{}=\"{}*\"", cond_name, pattern));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!("{}=\"*{}\"", cond_name, pattern));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries.push(format!("{}=\"*{}*\"", cond_name, pattern));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" OR ");
                        query_str.push_str(format!("({})", joined_sub_queries).as_str());
                    }
                    _ => {}
                };
                if !query_str.is_empty() {
                    conditions_list.push(query_str);
                }
            }
            let mut condition_query = String::new();
            condition_query.push('(');
            condition_query.push_str(conditions_list.join(" AND ").as_str());
            condition_query.push(')');
            condition_queries.push((sub_rule_name.to_string(), condition_query));
        }

        // Check the conditions of this subrule
        for condition in conditions.clone() {
            match condition {
                SigmaDetectionCondition::Plain(cond) => match cond {
                    ConditionExpression::Any(pattern) => {
                        let pattern = pattern.replace("*", "");
                        let matches: Vec<String> = condition_queries
                            .iter()
                            .filter(|x| x.0.contains(&pattern))
                            .map(|x| x.1.clone())
                            .collect();
                        if matches.len() > 1 {
                            query_str.push('(');
                            query_str.push_str(matches.join(" OR ").as_str());
                            query_str.push(')');
                        } else {
                            query_str.push_str(matches[0].clone().as_str());
                        }
                    }
                    ConditionExpression::All(pattern) => {
                        let pattern = pattern.replace("*", "");
                        let matches: Vec<String> = condition_queries
                            .iter()
                            .filter(|x| x.0.contains(&pattern.trim()))
                            .map(|x| x.1.clone())
                            .collect();
                        if matches.len() > 1 {
                            query_str.push('(');
                            query_str.push_str(matches.join(" AND ").as_str());
                            query_str.push(')');
                        } else {
                            query_str.push_str(matches[0].clone().as_str());
                        }
                    }
                    ConditionExpression::Not(cond_expr) => {
                        query_str.push_str(" NOT ");
                        match cond_expr.as_ref() {
                            ConditionExpression::Any(pattern) => {
                                let pattern = pattern.replace("*", "");
                                let matches: Vec<String> = condition_queries
                                    .iter()
                                    .filter(|x| x.0.contains(&pattern))
                                    .map(|x| x.1.clone())
                                    .collect();
                                if matches.len() > 1 {
                                    query_str.push('(');
                                    query_str.push_str(matches.join(" OR ").as_str());
                                    query_str.push(')');
                                } else {
                                    query_str.push_str(matches[0].clone().as_str());
                                }
                            }
                            ConditionExpression::All(pattern) => {
                                let pattern = pattern.replace("*", "");
                                let matches: Vec<String> = condition_queries
                                    .iter()
                                    .filter(|x| x.0.contains(&pattern))
                                    .map(|x| x.1.clone())
                                    .collect();
                                if matches.len() > 1 {
                                    query_str.push('(');
                                    query_str.push_str(matches.join(" AND ").as_str());
                                    query_str.push(')');
                                } else {
                                    query_str.push_str(matches[0].clone().as_str());
                                }
                            }
                            _ => {}
                        }
                    }
                },
                SigmaDetectionCondition::And(cond) => {
                    query_str.push_str(" AND ");
                    match cond {
                        ConditionExpression::Any(pattern) => {
                            let pattern = pattern.replace("*", "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" OR ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::All(pattern) => {
                            let pattern = pattern.replace("*", "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" AND ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::Not(cond_expr) => {
                            query_str.push_str(" NOT ");
                            match cond_expr.as_ref() {
                                ConditionExpression::Any(pattern) => {
                                    let pattern = pattern.replace("*", "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push('(');
                                        query_str.push_str(matches.join(" OR ").as_str());
                                        query_str.push(')');
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                ConditionExpression::All(pattern) => {
                                    let pattern = pattern.replace("*", "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push('(');
                                        query_str.push_str(matches.join(" AND ").as_str());
                                        query_str.push(')');
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                SigmaDetectionCondition::Or(cond) => {
                    query_str.push_str(" OR ");
                    match cond {
                        ConditionExpression::Any(pattern) => {
                            let pattern = pattern.replace("*", "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" OR ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::All(pattern) => {
                            let pattern = pattern.replace("*", "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" AND ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::Not(cond_expr) => {
                            query_str.push_str(" NOT ");
                            match cond_expr.as_ref() {
                                ConditionExpression::Any(pattern) => {
                                    let pattern = pattern.replace("*", "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push('(');
                                        query_str.push_str(matches.join(" OR ").as_str());
                                        query_str.push(')');
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                ConditionExpression::All(pattern) => {
                                    let pattern = pattern.replace("*", "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push('(');
                                        query_str.push_str(matches.join(" AND ").as_str());
                                        query_str.push(')');
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
        query_str.clone()
    }
}

#[cfg(test)]
mod tests {
    use crate::backend::splunk::SplunkBackend;
    use crate::backend::QueryBuilder;
    use crate::parse_sigma_rule;
    use std::env::current_dir;

    #[test]
    pub fn query_building() {
        let _7zip_rule_path = current_dir()
            .unwrap()
            .join("data")
            .join("7zip_sigma_rule.yml")
            .display()
            .to_string();
        let expected_query_str = r###"index=* source="WinEventLog:*" AND (((AuditPolicyChanges="*%%8448*" OR AuditPolicyChanges="*%%8450*") AND EventID="4719" AND (SubcategoryGuid="{0CCE9215-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE922B-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9240-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9210-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9211-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9212-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE921B-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE922F-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9230-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9235-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9236-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9237-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE923F-69AE-11D9-BED3-505054503030}" OR SubcategoryGuid="{0CCE9242-69AE-11D9-BED3-505054503030}")) OR (AuditPolicyChanges="*%%8448*" AND EventID="4719" AND SubcategoryGuid="{0CCE9217-69AE-11D9-BED3-505054503030}"))"###;
        let rule = parse_sigma_rule(_7zip_rule_path.as_str()).unwrap();
        let backend = SplunkBackend::default();
        let query = backend.build_query(&rule);
        println!("{}", query);
        assert_eq!(query.as_str(), expected_query_str);
    }
}
