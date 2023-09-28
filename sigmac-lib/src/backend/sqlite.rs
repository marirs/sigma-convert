use crate::backend::sql::SQLBackend;
use crate::backend::{BackEnd, QueryBuilder};
use crate::prelude::rule::sigma::SigmaRule;

#[derive(Clone, Debug, Default)]
pub struct SQLiteBackend {}

impl BackEnd for SQLiteBackend {
    fn convert_rule(&self, sigma_rule: SigmaRule) -> String {
        let query = self.build_query(&sigma_rule);
        format!("SELECT * FROM eventlog WHERE {query}")
    }
}

impl QueryBuilder for SQLiteBackend {
    fn build_query(&self, rule: &SigmaRule) -> String {
        SQLBackend::default().build_query(rule)
    }
}
