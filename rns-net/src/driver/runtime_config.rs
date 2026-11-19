//! Runtime config: the settings a running node lets its operator read
//! and change, grouped by the interface type or service they belong to.

mod auto;
mod backbone;
mod backbone_pool;
mod generic;
mod i2p;
mod keys;
mod pipe;
mod registration;
mod rnode;
mod tcp;
mod udp;
mod values;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeConfigFamily {
    #[cfg(feature = "iface-backbone")]
    Backbone,
    #[cfg(feature = "iface-backbone")]
    BackboneClient,
    #[cfg(feature = "iface-tcp")]
    TcpServer,
    #[cfg(feature = "iface-tcp")]
    TcpClient,
    #[cfg(feature = "iface-udp")]
    Udp,
    #[cfg(feature = "iface-auto")]
    Auto,
    #[cfg(feature = "iface-i2p")]
    I2p,
    #[cfg(feature = "iface-pipe")]
    Pipe,
    #[cfg(feature = "iface-rnode")]
    Rnode,
    Interface,
}

#[cfg(feature = "iface-backbone")]
pub(crate) use crate::common::discovery::parse_version_tuple;

#[cfg(all(test, feature = "iface-backbone"))]
mod duration_value_tests {
    use super::*;
    use crate::interface::backbone::BackboneClientRuntime;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    struct NoopCallbacks;

    impl Callbacks for NoopCallbacks {
        fn on_announce(&mut self, _: crate::common::destination::AnnouncedIdentity) {}
        fn on_path_updated(&mut self, _: rns_core::types::DestHash, _: u8) {}
        fn on_local_delivery(
            &mut self,
            _: rns_core::types::DestHash,
            _: Vec<u8>,
            _: rns_core::types::PacketHash,
        ) {
        }
    }

    fn driver_with_backbone_client(
        name: &str,
    ) -> (Driver, Arc<std::sync::Mutex<BackboneClientRuntime>>) {
        let (tx, rx) = crate::event::channel();
        let mut driver = Driver::new(
            super::super::tests::make_transport_config(false),
            rx,
            tx,
            Box::new(NoopCallbacks),
        );
        driver.set_tick_interval_handle(Arc::new(AtomicU64::new(1000)));
        let startup = BackboneClientRuntime {
            reconnect_wait: Duration::from_secs(5),
            max_reconnect_tries: Some(3),
            connect_timeout: Duration::from_secs(5),
        };
        let runtime = Arc::new(std::sync::Mutex::new(startup.clone()));
        driver.register_backbone_client_runtime(BackboneClientRuntimeConfigHandle {
            interface_name: name.to_string(),
            runtime: runtime.clone(),
            startup,
        });
        (driver, runtime)
    }

    #[test]
    fn expect_f64_rejects_non_finite_values() {
        for value in [f64::INFINITY, f64::NEG_INFINITY, f64::NAN, -1.0] {
            let err = Driver::expect_f64(RuntimeConfigValue::Float(value), "k").unwrap_err();
            assert_eq!(err.code, RuntimeConfigErrorCode::InvalidValue, "{value}");
        }
        assert_eq!(
            Driver::expect_f64(RuntimeConfigValue::Float(1.5), "k").unwrap(),
            1.5
        );
    }

    #[test]
    fn out_of_range_duration_values_return_errors_and_keep_runtime_usable() {
        let (mut driver, runtime) = driver_with_backbone_client("uplink");
        for key in [
            "backbone_client.uplink.connect_timeout_secs",
            "backbone_client.uplink.reconnect_wait_secs",
        ] {
            for value in [
                RuntimeConfigValue::Float(f64::INFINITY),
                RuntimeConfigValue::Float(f64::NAN),
                RuntimeConfigValue::Float(-1.0),
                RuntimeConfigValue::Int(-1),
                RuntimeConfigValue::Float(1e300),
            ] {
                let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
                    key: key.into(),
                    value: value.clone(),
                });
                let QueryResponse::RuntimeConfigSet(Err(err)) = response else {
                    panic!("expected {key} = {value:?} to be rejected");
                };
                assert_eq!(err.code, RuntimeConfigErrorCode::InvalidValue);
            }
        }
        assert!(!runtime.is_poisoned());
        assert_eq!(
            runtime.lock().unwrap().connect_timeout,
            Duration::from_secs(5)
        );
        assert_eq!(
            runtime.lock().unwrap().reconnect_wait,
            Duration::from_secs(5)
        );

        let response = driver.handle_query_mut(QueryRequest::SetRuntimeConfig {
            key: "backbone_client.uplink.connect_timeout_secs".into(),
            value: RuntimeConfigValue::Float(2.5),
        });
        let QueryResponse::RuntimeConfigSet(Ok(entry)) = response else {
            panic!("expected runtime config set success");
        };
        assert_eq!(entry.value, RuntimeConfigValue::Float(2.5));
        assert_eq!(
            runtime.lock().unwrap().connect_timeout,
            Duration::from_millis(2500)
        );
    }
}
