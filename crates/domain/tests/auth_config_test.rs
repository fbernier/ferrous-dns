use ferrous_dns_domain::AuthConfig;

#[test]
fn admin_username_defaults_to_admin_whether_or_not_the_table_is_present() {
    for toml_src in ["", "[admin]\n", "enabled = true\n"] {
        let auth: AuthConfig = toml::from_str(toml_src).unwrap();
        assert_eq!(auth.admin.username, "admin", "{toml_src:?}");
    }
    assert_eq!(AuthConfig::default().admin.username, "admin");
}
