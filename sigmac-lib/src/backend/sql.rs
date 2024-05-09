use crate::backend::{BackEnd, QueryBuilder};
use crate::prelude::rule::sigma::{ConditionExpression, SigmaDetectionCondition};
use crate::prelude::SiemField;
use crate::sigma::components::rule::sigma::SigmaRule;
use crate::sigma::components::rule::RuleOperator;
use crate::sigma::components::rule::SiemRule;
use crate::utils::parse_condition;
use std::process::exit;

#[derive(Clone, Debug, Default)]
pub struct SQLBackend {}

impl BackEnd for SQLBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        let query = self.build_query(&sigma_rule);
        format!("SELECT * FROM eventlog WHERE {query}")
    }
}

impl QueryBuilder for SQLBackend {
    fn build_query(&self, rule: &SigmaRule) -> String {
        let mut query_str = String::new();
        let siem_rule: SiemRule = rule.clone().into();
        let conditions = match parse_condition(rule.detection.condition.to_string().as_str()) {
            Ok(conds) => conds,
            Err(e) => {
                eprintln!("{:?}", e);
                exit(1);
            }
        };
        let mut condition_queries: Vec<(String, String)> = vec![];
        for (sub_rule_name, sub_rule) in siem_rule.subrules.as_ref().iter() {
            // for conditions in subrules.
            let mut conditions_list = vec![];
            let mut subrule_conditions = vec![];
            subrule_conditions.append(&mut sub_rule.conditions.clone());
            for condition in &subrule_conditions {
                let mut query_str = String::new();
                let (cond_name, cond_oper) =
                    (condition.field.to_string(), condition.operator.clone());
                let mapped_cond_name = cond_name;
                match cond_oper.clone() {
                    RuleOperator::StartsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!("{mapped_cond_name} = '{mapped_cond_name}' LIKE '{pattern}%'")
                                .as_str(),
                        );
                    }
                    RuleOperator::EndsWith(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!("{mapped_cond_name} = '{mapped_cond_name}' LIKE '%{pattern}'")
                                .as_str(),
                        );
                    }
                    RuleOperator::Contains(mut pattern) => {
                        pattern = pattern.replace('\\', "\\\\");
                        query_str.push_str(
                            format!(
                                "{mapped_cond_name} = {mapped_cond_name} CONTAINS \"{pattern}\""
                            )
                            .as_str(),
                        );
                    }
                    RuleOperator::Equals(field) => match field {
                        SiemField::Array(elements) => {
                            let joined_query = elements
                                .iter()
                                .map(|val| format!("{mapped_cond_name} LIKE \"{val}\" ESCAPE '\\'"))
                                .collect::<Vec<_>>()
                                .join(" OR ");
                            query_str.push_str(format!("({joined_query})").as_str())
                        }
                        _ => {
                            query_str.push_str(
                                format!("{mapped_cond_name} LIKE \"{field}\" ESCAPE '\\'").as_str(),
                            );
                        }
                    },
                    RuleOperator::Any(cond_list) => {
                        let cond_name = mapped_cond_name.clone();
                        let mut sub_queries = vec![];
                        let mut eq_sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    eq_sub_queries
                                        .push(format!("{cond_name} LIKE \"{val}\" ESCAPE '\\'"));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{cond_name} = '{cond_name}' LIKE '{pattern}%'"
                                    ));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{cond_name} = '{cond_name}' LIKE '%{pattern}'"
                                    ));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries.push(format!(
                                        "{cond_name} = {cond_name} CONTAINS \"{pattern}\""
                                    ));
                                }
                                _ => {}
                            }
                        }
                        if !eq_sub_queries.is_empty() {
                            sub_queries.push(eq_sub_queries.join(" OR "));
                        }
                        let joined_sub_queries = sub_queries.join(", ");
                        query_str.push_str(format!("({})", joined_sub_queries).as_str());
                    }
                    RuleOperator::All(cond_list) => {
                        let cond_name = mapped_cond_name.clone();
                        let mut sub_queries = vec![];
                        for cond in cond_list {
                            match cond.as_ref() {
                                RuleOperator::Equals(val) => {
                                    sub_queries
                                        .push(format!("{cond_name} LIKE \"{val}\" ESCAPE '\\'"));
                                }
                                RuleOperator::StartsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{cond_name} = '{cond_name}' LIKE '{pattern}%'"
                                    ));
                                }
                                RuleOperator::EndsWith(pattern) => {
                                    sub_queries.push(format!(
                                        "{cond_name} = '{cond_name}' LIKE '%{pattern}'"
                                    ));
                                }
                                RuleOperator::Contains(pattern) => {
                                    sub_queries.push(format!(
                                        "{cond_name} = {cond_name} CONTAINS \"{pattern}\""
                                    ));
                                }
                                _ => {}
                            }
                        }
                        let joined_sub_queries = sub_queries.join(" AND ");
                        query_str.push_str(format!("({joined_sub_queries})").as_str());
                    }
                    _ => {}
                };
                if !query_str.is_empty() {
                    conditions_list.push(query_str);
                }
            }
            let mut condition_query = String::new();
            condition_query.push_str(format!("({})", conditions_list.join(" AND ")).as_str());
            condition_queries.push((sub_rule_name.to_string(), condition_query));
        }

        // Check the conditions of this subrule
        for condition in conditions {
            match condition {
                SigmaDetectionCondition::Plain(cond) => match cond {
                    ConditionExpression::Any(pattern) => {
                        let pattern = pattern.replace('*', "");
                        let pattern = pattern.replace(' ', "");
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
                        let pattern = pattern.replace('*', "");
                        let pattern = pattern.replace(' ', "");
                        let matches: Vec<String> = condition_queries
                            .iter()
                            .filter(|x| x.0.contains(pattern.trim()))
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
                                let pattern = pattern.replace('*', "");
                                let pattern = pattern.replace(' ', "");
                                let matches: Vec<String> = condition_queries
                                    .iter()
                                    .filter(|x| x.0.contains(&pattern))
                                    .map(|x| x.1.clone())
                                    .collect();
                                if matches.len() > 1 {
                                    query_str.push('(');
                                    query_str.push_str(matches.join(" or ").as_str());
                                    query_str.push(')');
                                } else {
                                    query_str.push_str(matches[0].clone().as_str());
                                }
                            }
                            ConditionExpression::All(pattern) => {
                                let pattern = pattern.replace('*', "");
                                let pattern = pattern.replace(' ', "");
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
                            let pattern = pattern.replace('*', "");
                            let pattern = pattern.replace(' ', "");
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
                            let pattern = pattern.replace('*', "");
                            let pattern = pattern.replace(' ', "");
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
                                    let pattern = pattern.replace('*', "");
                                    let pattern = pattern.replace(' ', "");
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
                                    let pattern = pattern.replace('*', "");
                                    let pattern = pattern.replace(' ', "");
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
                    query_str.push_str(" or ");
                    match cond {
                        ConditionExpression::Any(pattern) => {
                            let pattern = pattern.replace('*', "");
                            let pattern = pattern.replace(' ', "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" or ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::All(pattern) => {
                            let pattern = pattern.replace('*', "");
                            let pattern = pattern.replace(' ', "");
                            let matches: Vec<String> = condition_queries
                                .iter()
                                .filter(|x| x.0.contains(&pattern))
                                .map(|x| x.1.clone())
                                .collect();
                            if matches.len() > 1 {
                                query_str.push('(');
                                query_str.push_str(matches.join(" and ").as_str());
                            } else {
                                query_str.push_str(matches[0].clone().as_str());
                            }
                        }
                        ConditionExpression::Not(cond_expr) => {
                            query_str.push_str(" not ");
                            match cond_expr.as_ref() {
                                ConditionExpression::Any(pattern) => {
                                    let pattern = pattern.replace('*', "");
                                    let pattern = pattern.replace(' ', "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push_str(
                                            format!("({})", matches.join(" or ")).as_str(),
                                        );
                                    } else {
                                        query_str.push_str(matches[0].clone().as_str());
                                    }
                                }
                                ConditionExpression::All(pattern) => {
                                    let pattern = pattern.replace('*', "");
                                    let pattern = pattern.replace(' ', "");
                                    let matches: Vec<String> = condition_queries
                                        .iter()
                                        .filter(|x| x.0.contains(&pattern))
                                        .map(|x| x.1.clone())
                                        .collect();
                                    if matches.len() > 1 {
                                        query_str.push_str(
                                            format!("({})", matches.join(" and ")).as_str(),
                                        );
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
