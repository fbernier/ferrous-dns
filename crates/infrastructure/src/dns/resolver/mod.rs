pub mod builder;
pub mod cache_layer;
pub mod core;
pub mod dns64_layer;
pub mod dnssec_layer;
pub mod filtered_resolver;
pub mod filters;
pub mod local_ptr;
pub mod local_wildcard;

pub use builder::ResolverBuilder;
pub use cache_layer::CachedResolver;
pub use core::CoreResolver;
pub use dns64_layer::Dns64Resolver;
pub use dnssec_layer::DnssecResolver;
pub use filtered_resolver::FilteredResolver;
pub use filters::{NonFqdn, QueryFilters};

pub use local_ptr::{LocalPtrResolver, PtrMap, PtrRegistry};
pub use local_wildcard::{LocalWildcardResolver, WildcardAnswer, WildcardMap, WildcardRegistry};
