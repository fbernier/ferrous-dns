use ferrous_dns_application::ports::ServiceCatalogPort;
use ferrous_dns_domain::ServiceDefinition;
use ferrous_dns_infrastructure::service_catalog::{CompositeServiceCatalog, ServiceCatalog};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

fn custom(id: &str) -> ServiceDefinition {
    ServiceDefinition {
        id: Arc::from(id),
        name: Arc::from(id),
        category_id: Arc::from("custom"),
        category_name: Arc::from("Custom"),
        icon_svg: Arc::from(""),
        rules: vec![Arc::from(format!("||{id}.example^").as_str())],
        is_custom: true,
    }
}

#[test]
fn test_get_by_id_never_returns_a_different_service_during_reload() {
    let catalog = Arc::new(CompositeServiceCatalog::new(ServiceCatalog::load()));
    let (a, b) = (custom("custom-a"), custom("custom-b"));
    catalog.reload_custom(vec![a.clone(), b.clone()]);

    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let catalog = Arc::clone(&catalog);
        let stop = Arc::clone(&stop);
        thread::spawn(move || {
            let mut flip = false;
            while !stop.load(Ordering::Relaxed) {
                // Same services, swapped positions: a stale index points at the other one.
                let list = if flip {
                    vec![a.clone(), b.clone()]
                } else {
                    vec![b.clone(), a.clone()]
                };
                catalog.reload_custom(list);
                flip = !flip;
            }
        })
    };

    let mut mismatches = 0u32;
    for _ in 0..200_000 {
        match catalog.get_by_id("custom-a") {
            Some(def) if &*def.id == "custom-a" => {}
            _ => mismatches += 1,
        }
    }
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("writer thread");

    assert_eq!(mismatches, 0, "lookups returned the wrong service or none");
}

#[test]
fn test_static_service_wins_over_custom_with_same_id() {
    let static_catalog = ServiceCatalog::load();
    let builtin = static_catalog.all()[0].clone();
    let catalog = CompositeServiceCatalog::new(static_catalog);
    catalog.reload_custom(vec![custom(&builtin.id)]);

    let found = catalog.get_by_id(&builtin.id).expect("builtin present");
    assert!(!found.is_custom);
}

#[test]
fn test_reload_custom_replaces_previous_custom_services() {
    let catalog = CompositeServiceCatalog::new(ServiceCatalog::load());
    catalog.reload_custom(vec![custom("custom-old")]);
    catalog.reload_custom(vec![custom("custom-new")]);

    assert!(catalog.get_by_id("custom-old").is_none());
    assert!(catalog.get_by_id("custom-new").is_some());
    let customs: Vec<_> = catalog.all().into_iter().filter(|s| s.is_custom).collect();
    assert_eq!(customs.len(), 1);
    assert_eq!(&*customs[0].id, "custom-new");
}
