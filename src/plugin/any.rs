use std::any::Any;

/// Type-erasure seam used for native plugin service discovery.
#[doc(hidden)]
pub trait PluginAny: Any {
    fn as_any(&self) -> &dyn Any;
}

impl<T: Any> PluginAny for T {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
