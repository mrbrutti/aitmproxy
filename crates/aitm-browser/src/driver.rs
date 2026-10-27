//! The chromiumoxide-backed [`BrowserDriver`].
//!
//! `ChromeDriver::launch` starts headless Chromium with the proxy as its
//! upstream (`--proxy-server`), opens one page, and trusts the proxy CA at
//! runtime via CDP `Security.setIgnoreCertificateErrors`. Every primitive then
//! drives that page.

use std::collections::BTreeMap;

use aitm_core::{BrowserConfig, BrowserDriver, ClickTarget, NavOutcome, Value};
use chromiumoxide::browser::{Browser, BrowserConfig as CdpConfig};
use chromiumoxide::cdp::browser_protocol::security::SetIgnoreCertificateErrorsParams;
use chromiumoxide::layout::Point;
use chromiumoxide::page::{Page, ScreenshotParams};
use futures::future::BoxFuture;
use futures::StreamExt;
use tokio::task::JoinHandle;

/// Headless Chromium, routed through the proxy, driven over CDP.
pub struct ChromeDriver {
    browser: Browser,
    page: Page,
    nav_timeout: std::time::Duration,
    handler: JoinHandle<()>,
}

/// Chromium launch flags derived from the config: route everything — loopback
/// included, which Chromium otherwise bypasses — through the proxy.
pub(crate) fn launch_args(config: &BrowserConfig) -> Vec<String> {
    vec![
        format!("--proxy-server={}", config.proxy_addr),
        "--proxy-bypass-list=<-loopback>".to_string(),
    ]
}

/// Convert a CDP evaluation result into a bus [`Value`].
pub(crate) fn json_to_value(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Null,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i),
            None => Value::Float(n.as_f64().unwrap_or(f64::NAN)),
        },
        serde_json::Value::String(s) => Value::Str(s.clone()),
        serde_json::Value::Array(items) => Value::Array(items.iter().map(json_to_value).collect()),
        serde_json::Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), json_to_value(v)))
                .collect::<BTreeMap<_, _>>(),
        ),
    }
}

impl ChromeDriver {
    /// Launch Chromium with the proxy upstream and the CA-trust posture in `config`.
    pub async fn launch(config: &BrowserConfig) -> anyhow::Result<Self> {
        let mut builder = CdpConfig::builder().args(launch_args(config));
        if !config.headless {
            builder = builder.with_head();
        }
        let cdp_config = builder.build().map_err(anyhow::Error::msg)?;

        let (browser, mut events) = Browser::launch(cdp_config).await?;
        // The handler must be polled for the CDP connection to make progress.
        let handler = tokio::spawn(async move {
            while let Some(event) = events.next().await {
                if event.is_err() {
                    break;
                }
            }
        });

        let page = browser.new_page("about:blank").await?;
        if config.ignore_cert_errors {
            page.execute(SetIgnoreCertificateErrorsParams::new(true))
                .await?;
        }

        Ok(Self {
            browser,
            page,
            nav_timeout: config.nav_timeout,
            handler,
        })
    }

    /// Close the browser process.
    pub async fn close(mut self) -> anyhow::Result<()> {
        self.browser.close().await?;
        self.handler.abort();
        Ok(())
    }
}

impl Drop for ChromeDriver {
    fn drop(&mut self) {
        self.handler.abort();
    }
}

impl BrowserDriver for ChromeDriver {
    fn navigate(&self, url: &str) -> BoxFuture<'_, anyhow::Result<NavOutcome>> {
        let url = url.to_string();
        Box::pin(async move {
            let nav = async {
                self.page.goto(url.as_str()).await?;
                self.page.wait_for_navigation().await?;
                anyhow::Ok(())
            };
            tokio::time::timeout(self.nav_timeout, nav)
                .await
                .map_err(|_| anyhow::anyhow!("navigation to {url} timed out"))??;
            let final_url = self.page.url().await?.unwrap_or(url);
            // The HTTP status is not surfaced by CDP's Page.navigate; the proxy's
            // captured flow for this navigation carries it.
            Ok(NavOutcome {
                final_url,
                status: None,
            })
        })
    }

    fn click(&self, target: ClickTarget) -> BoxFuture<'_, anyhow::Result<()>> {
        Box::pin(async move {
            match target {
                ClickTarget::Selector(selector) => {
                    self.page.find_element(selector).await?.click().await?;
                }
                ClickTarget::Point { x, y } => {
                    self.page.click(Point { x, y }).await?;
                }
            }
            Ok(())
        })
    }

    fn type_text(&self, selector: &str, text: &str) -> BoxFuture<'_, anyhow::Result<()>> {
        let selector = selector.to_string();
        let text = text.to_string();
        Box::pin(async move {
            self.page
                .find_element(selector)
                .await?
                .click()
                .await?
                .type_str(text)
                .await?;
            Ok(())
        })
    }

    fn screenshot(&self) -> BoxFuture<'_, anyhow::Result<Vec<u8>>> {
        Box::pin(async move {
            let png = self
                .page
                .screenshot(ScreenshotParams::builder().build())
                .await?;
            Ok(png)
        })
    }

    fn eval(&self, expr: &str) -> BoxFuture<'_, anyhow::Result<Value>> {
        let expr = expr.to_string();
        Box::pin(async move {
            let result = self.page.evaluate(expr).await?;
            Ok(result.value().map(json_to_value).unwrap_or(Value::Null))
        })
    }

    fn get_dom(&self) -> BoxFuture<'_, anyhow::Result<String>> {
        Box::pin(async move { Ok(self.page.content().await?) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aitm_core::{BrowserConfig, Value};

    #[test]
    fn launch_args_route_through_the_proxy() {
        let config = BrowserConfig {
            proxy_addr: "127.0.0.1:18080".parse().expect("socket addr"),
            ..BrowserConfig::default()
        };
        let args = launch_args(&config);
        assert!(
            args.iter().any(|a| a == "--proxy-server=127.0.0.1:18080"),
            "no --proxy-server flag in {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "--proxy-bypass-list=<-loopback>"),
            "loopback would bypass the proxy: {args:?}"
        );
    }

    #[test]
    fn json_to_value_maps_page_results() {
        assert_eq!(json_to_value(&serde_json::json!(2)), Value::Int(2));
        assert_eq!(json_to_value(&serde_json::json!(1.5)), Value::Float(1.5));
        assert_eq!(
            json_to_value(&serde_json::json!("hi")),
            Value::Str("hi".into())
        );
        assert_eq!(json_to_value(&serde_json::json!(true)), Value::Bool(true));
        assert_eq!(json_to_value(&serde_json::json!(null)), Value::Null);
        assert_eq!(
            json_to_value(&serde_json::json!([1, "a"])),
            Value::Array(vec![Value::Int(1), Value::Str("a".into())])
        );
        let Value::Object(obj) = json_to_value(&serde_json::json!({"k": 3})) else {
            panic!("expected an object");
        };
        assert_eq!(obj.get("k"), Some(&Value::Int(3)));
    }
}
