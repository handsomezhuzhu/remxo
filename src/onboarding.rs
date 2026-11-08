//! First-run onboarding guidance.
//!
//! The npm package ships no install banner, so a new user's first command has to
//! tell them what to do next. This module derives that guidance from non-secret
//! facts only: whether the configuration and Vault files exist, whether the
//! Vault is locked, and how many hosts are registered.
//!
//! The guidance is intentionally limited to the human-readable output paths.
//! `--json` output stays a single machine-readable document, so adding a hint
//! there would break consumers.

use crate::config::{AppPaths, UiLanguage};

/// How far a local installation has progressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Onboarding {
    /// Neither `config.toml` nor `vault.json` exists.
    Uninitialized,
    /// `config.toml` exists but the Vault is missing: an interrupted `init`.
    VaultMissing,
    /// The Vault exists and is locked, so it cannot serve credentials yet.
    Locked,
    /// The Vault is unlocked but no host is registered.
    NoHosts,
    /// The Vault is unlocked and at least one host is registered.
    Ready,
}

impl Onboarding {
    /// The states that are certain from file presence alone.
    ///
    /// Returns `None` once a Vault exists, because telling "locked" from
    /// "unlocked" needs a Broker round-trip. Error paths use this to avoid
    /// guessing a lock state they cannot know.
    pub fn from_files(paths: &AppPaths) -> Option<Self> {
        if paths.vault().exists() {
            return None;
        }
        Some(if paths.config.exists() {
            Self::VaultMissing
        } else {
            Self::Uninitialized
        })
    }

    /// Derive the full state. `vault_locked` is the caller's view of the lock
    /// state and is ignored when no Vault file exists.
    pub fn detect(paths: &AppPaths, vault_locked: bool, hosts: usize) -> Self {
        if let Some(state) = Self::from_files(paths) {
            return state;
        }
        if vault_locked {
            return Self::Locked;
        }
        if hosts == 0 {
            return Self::NoHosts;
        }
        Self::Ready
    }

    /// The single next command for this state, or `None` once setup is complete.
    ///
    /// Returning `None` for [`Onboarding::Ready`] keeps an established
    /// installation quiet instead of repeating advice on every invocation.
    pub fn hint(self, language: UiLanguage) -> Option<&'static str> {
        match self {
            Self::Ready => None,
            Self::Uninitialized => Some(language.text(
                "Next: remxo init --lang en   (or --lang zh-CN; sets the master password and creates an empty host inventory)",
                "下一步：remxo init --lang zh-CN   （设置主密码并创建空主机清单）",
            )),
            Self::VaultMissing => Some(language.text(
                "Next: remxo init   (your existing config is preserved; only the missing Vault is created)",
                "下一步：remxo init   （保留现有配置，只创建缺失的 Vault）",
            )),
            Self::Locked => Some(language.text(
                "Next: remxo unlock   (enter the master password)",
                "下一步：remxo unlock   （输入主密码）",
            )),
            Self::NoHosts => Some(language.text(
                "Next: remxo host add <alias>   (register your first host)",
                "下一步：remxo host add <别名>   （登记第一台主机）",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths(root: &std::path::Path) -> AppPaths {
        AppPaths::new(Some(root.join("config.toml")))
            .unwrap_or_else(|error| panic!("paths: {error}"))
    }

    fn seed(directory: &std::path::Path, config: bool, vault: bool) {
        if config {
            std::fs::write(directory.join("config.toml"), "settings = {}\n")
                .unwrap_or_else(|error| panic!("write config: {error}"));
        }
        if vault {
            std::fs::write(directory.join("vault.json"), "{}\n")
                .unwrap_or_else(|error| panic!("write vault: {error}"));
        }
    }

    #[test]
    fn a_bare_directory_is_uninitialized() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        let state = Onboarding::detect(&paths(directory.path()), true, 0);
        assert_eq!(state, Onboarding::Uninitialized);
        assert!(state.hint(UiLanguage::En).is_some());
    }

    #[test]
    fn config_without_vault_is_reported_as_an_interrupted_init() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        seed(directory.path(), true, false);
        let state = Onboarding::detect(&paths(directory.path()), true, 0);
        assert_eq!(state, Onboarding::VaultMissing);
        let hint = state.hint(UiLanguage::En).expect("hint");
        assert!(hint.contains("remxo init"), "{hint}");
    }

    #[test]
    fn an_existing_vault_reports_locked_then_host_less_then_ready() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        seed(directory.path(), true, true);
        let paths = paths(directory.path());
        assert_eq!(Onboarding::detect(&paths, true, 0), Onboarding::Locked);
        assert_eq!(Onboarding::detect(&paths, false, 0), Onboarding::NoHosts);
        assert_eq!(Onboarding::detect(&paths, false, 3), Onboarding::Ready);
    }

    #[test]
    fn a_ready_installation_stays_quiet() {
        let directory = tempfile::tempdir().unwrap_or_else(|error| panic!("tempdir: {error}"));
        seed(directory.path(), true, true);
        let state = Onboarding::detect(&paths(directory.path()), false, 1);
        assert_eq!(state, Onboarding::Ready);
        assert_eq!(state.hint(UiLanguage::ZhCn), None);
    }

    #[test]
    fn hints_are_bilingual_and_name_the_next_command() {
        for state in [
            Onboarding::Uninitialized,
            Onboarding::VaultMissing,
            Onboarding::Locked,
            Onboarding::NoHosts,
        ] {
            let english = state.hint(UiLanguage::En).expect("english hint");
            let chinese = state.hint(UiLanguage::ZhCn).expect("chinese hint");
            assert_ne!(english, chinese, "{state:?}");
            assert!(english.starts_with("Next: "), "{english}");
            assert!(chinese.starts_with("下一步："), "{chinese}");
        }
    }

    #[test]
    fn hints_never_ask_for_a_credential_inline() {
        for state in [
            Onboarding::Uninitialized,
            Onboarding::VaultMissing,
            Onboarding::Locked,
            Onboarding::NoHosts,
        ] {
            for language in [UiLanguage::En, UiLanguage::ZhCn] {
                let hint = state.hint(language).expect("hint");
                assert!(!hint.contains("password:"), "{hint}");
            }
        }
    }
}
