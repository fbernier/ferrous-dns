use ferrous_dns_application::ports::ServiceCatalogPort;
use ferrous_dns_domain::ServiceDefinition;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use super::ServiceCatalog;

/// Composite catalog that merges built-in (static) and custom (dynamic) services.
pub struct CompositeServiceCatalog {
    static_catalog: ServiceCatalog,
    custom: RwLock<CustomServices>,
}

/// List and index share one lock so a reader never pairs an index with a different list.
#[derive(Default)]
struct CustomServices {
    list: Vec<ServiceDefinition>,
    by_id: HashMap<Arc<str>, usize>,
}

impl CompositeServiceCatalog {
    pub fn new(static_catalog: ServiceCatalog) -> Self {
        Self {
            static_catalog,
            custom: RwLock::default(),
        }
    }
}

impl ServiceCatalogPort for CompositeServiceCatalog {
    fn get_by_id(&self, id: &str) -> Option<ServiceDefinition> {
        if let Some(def) = self.static_catalog.get_by_id(id) {
            return Some(def.clone());
        }

        let custom = self.custom.read().unwrap_or_else(|e| e.into_inner());
        custom
            .by_id
            .get(id)
            .and_then(|&idx| custom.list.get(idx))
            .cloned()
    }

    fn all(&self) -> Vec<ServiceDefinition> {
        let static_all = self.static_catalog.all();
        let custom = self.custom.read().unwrap_or_else(|e| e.into_inner());

        let mut result = Vec::with_capacity(static_all.len() + custom.list.len());
        result.extend_from_slice(static_all);
        result.extend_from_slice(&custom.list);
        result
    }

    fn normalized_rules_for(&self, service_id: &str) -> Vec<String> {
        if let Some(svc) = self.get_by_id(service_id) {
            return svc
                .rules
                .iter()
                .filter_map(|r| ServiceCatalog::normalize_rule(r))
                .collect();
        }
        vec![]
    }

    fn reload_custom(&self, custom: Vec<ServiceDefinition>) {
        let by_id = custom
            .iter()
            .enumerate()
            .map(|(idx, def)| (Arc::clone(&def.id), idx))
            .collect();
        let next = CustomServices {
            list: custom,
            by_id,
        };

        *self.custom.write().unwrap_or_else(|e| e.into_inner()) = next;
    }
}
