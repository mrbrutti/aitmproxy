//! The registry: the control plane's command table, the option store, and the
//! ordered plugin list. Built mutably at startup, then shared (`Arc<Registry>`)
//! with the frontends, which only read commands. The plugin chain (Task 8) locks
//! each plugin in turn to dispatch events, so plugins are held behind a `Mutex`.

use std::sync::{Arc, Mutex};

use indexmap::IndexMap;

use crate::command::Command;
use crate::plugin::Plugin;
use crate::value::Value;

/// A registered option: its current value and a human description.
struct OptionEntry {
    value: Value,
    #[allow(dead_code)]
    description: String,
}

/// The command table, option store, and ordered plugin list.
#[derive(Default)]
pub struct Registry {
    commands: IndexMap<String, Arc<dyn Command>>,
    options: IndexMap<String, OptionEntry>,
    plugins: Vec<Mutex<Box<dyn Plugin>>>,
}

impl Registry {
    /// An empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a command, keyed by its `name()`.
    pub fn add_command(&mut self, cmd: Arc<dyn Command>) {
        self.commands.insert(cmd.name().to_string(), cmd);
    }

    /// Register a plugin: run its `load` (which may register commands/options),
    /// then append it to the ordered chain.
    pub fn add_plugin(&mut self, mut plugin: Box<dyn Plugin>) {
        plugin.load(self);
        self.plugins.push(Mutex::new(plugin));
    }

    /// Look up a command by name.
    pub fn command(&self, name: &str) -> Option<&Arc<dyn Command>> {
        self.commands.get(name)
    }

    /// Iterate registered commands in registration order.
    pub fn commands(&self) -> impl Iterator<Item = &Arc<dyn Command>> {
        self.commands.values()
    }

    /// The ordered plugin list, each behind a `Mutex` so the chain can call
    /// `on_event` mutably while the registry is shared.
    pub fn plugins(&self) -> &[Mutex<Box<dyn Plugin>>] {
        &self.plugins
    }

    /// Register an option with a default value (mirrors a `ParamDef`).
    pub fn add_option(&mut self, name: &str, default: Value, description: &str) {
        self.options.entry(name.to_string()).or_insert(OptionEntry {
            value: default,
            description: description.to_string(),
        });
    }

    /// The current value of an option, if registered.
    pub fn option(&self, name: &str) -> Option<Value> {
        self.options.get(name).map(|o| o.value.clone())
    }

    /// Override an option's value (e.g. from config). Registers it if new.
    pub fn set_option(&mut self, name: &str, value: Value) {
        match self.options.get_mut(name) {
            Some(entry) => entry.value = value,
            None => {
                self.options.insert(
                    name.to_string(),
                    OptionEntry {
                        value,
                        description: String::new(),
                    },
                );
            }
        }
    }
}
