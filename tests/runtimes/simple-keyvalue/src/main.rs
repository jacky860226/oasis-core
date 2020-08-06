use std::sync::Arc;

use failure::{format_err, Fallible};
use io_context::Context as IoContext;

use oasis_core_keymanager_client::{KeyManagerClient, KeyPairId};
use oasis_core_runtime::{
    common::{
        crypto::{
            hash::Hash,
            mrae::deoxysii::{DeoxysII, KEY_SIZE, NONCE_SIZE, TAG_SIZE},
        },
        runtime::RuntimeId,
        version::Version,
    },
    executor::Executor,
    rak::RAK,
    register_runtime_txn_methods, runtime_context,
    storage::{StorageContext, MKVS},
    transaction::{dispatcher::CheckOnlySuccess, Context as TxnContext},
    version_from_cargo, Protocol, RpcDemux, RpcDispatcher, TxnDispatcher, TxnMethDispatcher,
};
use simple_keymanager::trusted_policy_signers;
use simple_keyvalue_api::{with_api, KeyValue};


use std::collections::BTreeMap;
use std::env;
use evmc_client::{host::HostContext as HostInterface, load, EvmcVm, EvmcLoaderErrorCode, types::*};

struct HostContext {
    storage: BTreeMap<Bytes32, Bytes32>,
}

impl HostContext {
    fn new() -> HostContext {
        HostContext {
            storage: BTreeMap::new(),
        }
    }
}

impl HostInterface for HostContext {
	fn account_exists(&mut self, _addr: &Address) -> bool {
		println!("Host: account_exists");
		return true;
	}
	fn get_storage(&mut self, _addr: &Address, key: &Bytes32) -> Bytes32 {
		println!("Host: get_storage");
		let value = self.storage.get(key);
		let ret: Bytes32;
		match value {
			Some(value) => ret = value.to_owned(),
			None => ret = [0u8; BYTES32_LENGTH],
		}
		println!("{:?} -> {:?}", hex::encode(key), hex::encode(ret));
		return ret;
	}
	fn set_storage(&mut self, _addr: &Address, key: &Bytes32, value: &Bytes32) -> StorageStatus {
		println!("Host: set_storage");
		println!("{:?} -> {:?}", hex::encode(key), hex::encode(value));
		self.storage.insert(key.to_owned(), value.to_owned());
		return StorageStatus::EVMC_STORAGE_MODIFIED;
	}
	fn get_balance(&mut self, _addr: &Address) -> Bytes32 {
		println!("Host: get_balance");
		return [0u8; BYTES32_LENGTH];
	}
	fn get_code_size(&mut self, _addr: &Address) -> usize {
		println!("Host: get_code_size");
		return 0;
	}
	fn get_code_hash(&mut self, _addr: &Address) -> Bytes32 {
		println!("Host: get_code_hash");
		return [0u8; BYTES32_LENGTH];
	}
	fn copy_code(
		&mut self,
		_addr: &Address,
		_offset: &usize,
		_buffer_data: &*mut u8,
		_buffer_size: &usize,
	) -> usize {
		println!("Host: copy_code");
		return 0;
	}
	fn selfdestruct(&mut self, _addr: &Address, _beneficiary: &Address) {
		println!("Host: selfdestruct");
	}
	fn get_tx_context(&mut self) -> (Bytes32, Address, Address, i64, i64, i64, Bytes32) {
		println!("Host: get_tx_context");
		return (
			[0u8; BYTES32_LENGTH],
			[0u8; ADDRESS_LENGTH],
			[0u8; ADDRESS_LENGTH],
			0,
			0,
			0,
			[0u8; BYTES32_LENGTH],
		);
	}
	fn get_block_hash(&mut self, _number: i64) -> Bytes32 {
		println!("Host: get_block_hash");
		return [0u8; BYTES32_LENGTH];
	}
	fn emit_log(&mut self, _addr: &Address, _topics: &Vec<Bytes32>, _data: &[u8]) {
		println!("Host: emit_log");
	}
	fn call(
		&mut self,
		_kind: CallKind,
		_destination: &Address,
		_sender: &Address,
		_value: &Bytes32,
		_input: &[u8],
		_gas: i64,
		_depth: i32,
		_is_static: bool,
	) -> (Vec<u8>, i64, Address, StatusCode) {
		println!("Host: call");
		return (
			vec![0u8; BYTES32_LENGTH],
			_gas,
			[0u8; ADDRESS_LENGTH],
			StatusCode::EVMC_SUCCESS,
		);
	}
}

impl Drop for HostContext {
    fn drop(&mut self) {
        println!("Dump storage:");
        for (key, value) in &self.storage {
            println!("{:?} -> {:?}", hex::encode(key), hex::encode(value));
        }
    }
}

struct Context {
    test_runtime_id: RuntimeId,
    km_client: Arc<dyn KeyManagerClient>,
    vm: EvmcVm,
    result: Result<EvmcLoaderErrorCode, &'static str>,
}

/// Return previously set runtime ID of this runtime.
fn get_runtime_id(_args: &(), ctx: &mut TxnContext) -> Fallible<Option<String>> {
    let rctx = runtime_context!(ctx, Context);

    Ok(Some(rctx.test_runtime_id.to_string()))
}

/// Insert a key/value pair.
fn insert(args: &KeyValue, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if args.value.as_bytes().len() > 128 {
        return Err(format_err!("Value too big to be inserted."));
    }
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    ctx.emit_txn_tag(b"kv_op", b"insert");
    ctx.emit_txn_tag(b"kv_key", args.key.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.insert(
            IoContext::create_child(&ctx.io_ctx),
            args.key.as_bytes(),
            args.value.as_bytes(),
        )
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Retrieve a key/value pair.
fn get(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    ctx.emit_txn_tag(b"kv_op", b"get");
    ctx.emit_txn_tag(b"kv_key", args.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.get(IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Remove a key/value pair.
fn remove(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if ctx.check_only {
        return Err(CheckOnlySuccess::default().into());
    }
    ctx.emit_txn_tag(b"kv_op", b"remove");
    ctx.emit_txn_tag(b"kv_key", args.as_bytes());

    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        mkvs.remove(IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// Helper for doing encrypted MKVS operations.
fn get_encryption_context(ctx: &mut TxnContext, key: &[u8]) -> Fallible<EncryptionContext> {
    let rctx = runtime_context!(ctx, Context);

    // Derive key pair ID based on key.
    let key_pair_id = KeyPairId::from(Hash::digest_bytes(key).as_ref());

    // Fetch encryption keys.
    let io_ctx = IoContext::create_child(&ctx.io_ctx);
    let result = rctx.km_client.get_or_create_keys(io_ctx, key_pair_id);
    let key = Executor::with_current(|executor| executor.block_on(result))?;

    Ok(EncryptionContext::new(key.state_key.as_ref()))
}

/// (encrypted) Insert a key/value pair.
fn enc_insert(args: &KeyValue, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    // NOTE: This is only for example purposes, the correct way would be
    //       to also generate a (deterministic) nonce.
    let nonce = [0u8; NONCE_SIZE];

    let enc_ctx = get_encryption_context(ctx, args.key.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.insert(
            mkvs,
            IoContext::create_child(&ctx.io_ctx),
            args.key.as_bytes(),
            args.value.as_bytes(),
            &nonce,
        )
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// (encrypted) Retrieve a key/value pair.
fn enc_get(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    let enc_ctx = get_encryption_context(ctx, args.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.get(mkvs, IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

/// (encrypted) Remove a key/value pair.
fn enc_remove(args: &String, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    let enc_ctx = get_encryption_context(ctx, args.as_bytes())?;
    let existing = StorageContext::with_current(|mkvs, _untrusted_local| {
        enc_ctx.remove(mkvs, IoContext::create_child(&ctx.io_ctx), args.as_bytes())
    });
    Ok(existing.map(|v| String::from_utf8(v)).transpose()?)
}

// #[cfg(not(target_env = "sgx"))]
fn exec(args: &Vec<u8>, ctx: &mut TxnContext) -> Fallible<Option<String>> {
    if cfg!(target_env = "sgx") {
        return Ok(Some("#[cfg(not(target_env = \"sgx\"))]".to_string()));
    }
    let rctx = runtime_context!(ctx, Context);
    let code = args;
	println!("result {:?}", rctx.result);
    println!("Instantiate: {:?}", (rctx.vm.get_name(), rctx.vm.get_version()));
    
    let host_context = HostContext::new();
    let (output, gas_left, status_code) = rctx.vm.execute(
        Box::new(host_context),
        Revision::EVMC_BYZANTIUM,
        CallKind::EVMC_CALL,
        false,
        123,
        50000000,
        &[32u8; 20],
        &[128u8; 20],
        &[0u8; 0],
        &[0u8; 32],
        &code[..],
        &[0u8; 32],
    );
    println!("Output:  {:?}", hex::encode(output));
    println!("GasLeft: {:?}", gas_left);
    println!("Status:  {:?}", status_code);
    //_vm.destroy();

    Ok(Some(format!("{}", hex::encode(output))))
}

/// A keyed storage encryption context, for use with a MKVS instance.
struct EncryptionContext {
    d2: DeoxysII,
}

impl EncryptionContext {
    /// Initialize a new EncryptionContext with the given MRAE key.
    pub fn new(key: &[u8]) -> Self {
        if key.len() != KEY_SIZE {
            panic!("mkvs: invalid encryption key size {}", key.len());
        }
        let mut raw_key = [0u8; KEY_SIZE];
        raw_key.copy_from_slice(&key[..KEY_SIZE]);

        let d2 = DeoxysII::new(&raw_key);
        //raw_key.zeroize();

        Self { d2 }
    }

    /// Get encrypted MKVS entry.
    pub fn get(&self, mkvs: &dyn MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.get(ctx, &key) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    /// Insert encrypted MKVS entry.
    pub fn insert(
        &self,
        mkvs: &mut dyn MKVS,
        ctx: IoContext,
        key: &[u8],
        value: &[u8],
        nonce: &[u8],
    ) -> Option<Vec<u8>> {
        let nonce = Self::derive_nonce(&nonce);
        let mut ciphertext = self.d2.seal(&nonce, value.to_vec(), vec![]);
        ciphertext.extend_from_slice(&nonce);

        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.insert(ctx, &key, &ciphertext) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    /// Remove encrypted MKVS entry.
    pub fn remove(&self, mkvs: &mut dyn MKVS, ctx: IoContext, key: &[u8]) -> Option<Vec<u8>> {
        let key = self.derive_encrypted_key(key);
        let ciphertext = match mkvs.remove(ctx, &key) {
            Some(ciphertext) => ciphertext,
            None => return None,
        };

        self.open(&ciphertext)
    }

    fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        // ciphertext || tag || nonce.
        if ciphertext.len() < TAG_SIZE + NONCE_SIZE {
            return None;
        }

        let nonce_offset = ciphertext.len() - NONCE_SIZE;
        let mut nonce = [0u8; NONCE_SIZE];
        nonce.copy_from_slice(&ciphertext[nonce_offset..]);
        let ciphertext = &ciphertext[..nonce_offset];

        let plaintext = self.d2.open(&nonce, ciphertext.to_vec(), vec![]);
        plaintext.ok()
    }

    fn derive_encrypted_key(&self, key: &[u8]) -> Vec<u8> {
        // XXX: The plan is eventually to use a lighter weight transform
        // for the key instead of a full fledged MRAE algorithm.  For now
        // approximate it with a Deoxys-II call with an all 0 nonce.

        let nonce = [0u8; NONCE_SIZE];
        self.d2.seal(&nonce, key.to_vec(), vec![])
    }

    fn derive_nonce(nonce: &[u8]) -> [u8; NONCE_SIZE] {
        // Just a copy for type safety.
        let mut n = [0u8; NONCE_SIZE];
        if nonce.len() != NONCE_SIZE {
            panic!("invalid nonce size: {}", nonce.len());
        }
        n.copy_from_slice(nonce);

        n
    }
}

fn main() {
    // Initializer.
    let init = |protocol: &Arc<Protocol>,
                rak: &Arc<RAK>,
                _rpc_demux: &mut RpcDemux,
                rpc: &mut RpcDispatcher|
     -> Option<Box<dyn TxnDispatcher>> {
        let mut txn = TxnMethDispatcher::new();
        with_api! { register_runtime_txn_methods!(txn, api); }

        // Create the key manager client.
        let rt_id = protocol.get_runtime_id();
        let km_client = Arc::new(oasis_core_keymanager_client::RemoteClient::new_runtime(
            rt_id,
            protocol.clone(),
            rak.clone(),
            1024,
            trusted_policy_signers(),
        ));
        let initializer_km_client = km_client.clone();

        #[cfg(not(target_env = "sgx"))]
        let _ = rpc;
        #[cfg(target_env = "sgx")]
        rpc.set_keymanager_policy_update_handler(Some(Box::new(move |raw_signed_policy| {
            km_client
                .set_policy(raw_signed_policy)
                .expect("failed to update km client policy");
        })));

        if cfg!(target_env = "sgx") {
            return Some(Box::new(txn));
        }

        txn.set_context_initializer(move |ctx: &mut TxnContext| {
            let lib_path = "/libssvm-evmc.so";
            let (_vm, _result) = load(lib_path);
            ctx.runtime = Box::new(Context {
                test_runtime_id: rt_id.clone(),
                km_client: initializer_km_client.clone(),
                vm: _vm,
                result: _result,
            })
        });

        Some(Box::new(txn))
    };

    // Start the runtime.
    oasis_core_runtime::start_runtime(Box::new(init), version_from_cargo!());
}
