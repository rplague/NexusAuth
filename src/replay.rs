//! nonce 去重（有界），供管理认证与入网认证复用。

use std::collections::{HashSet, VecDeque};

/// 进程内保留的 nonce 数量上限。
pub const MAX_SEEN_NONCES: usize = 10_000;

/// nonce 校验错误。
#[derive(Debug, PartialEq, Eq)]
pub enum ReplayError {
    /// nonce 为空
    Empty,
    /// nonce 重放
    Replay,
}

/// 有界 nonce 去重器。
#[derive(Default)]
pub struct ReplayGuard {
    seen: HashSet<String>,
    order: VecDeque<String>,
}

impl ReplayGuard {
    /// 登记一个 nonce；空值或重复值返回错误。
    pub fn check_and_insert(&mut self, nonce: &str) -> Result<(), ReplayError> {
        if nonce.is_empty() {
            return Err(ReplayError::Empty);
        }
        if self.seen.contains(nonce) {
            return Err(ReplayError::Replay);
        }
        self.seen.insert(nonce.to_string());
        self.order.push_back(nonce.to_string());
        while self.order.len() > MAX_SEEN_NONCES {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        Ok(())
    }
}
