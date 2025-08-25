// // use openmls::{
// //   prelude::{*, tls_codec::*},
// // };
// // use openmls_rust_crypto::OpenMlsRustCrypto;
// // use openmls_basic_credential::SignatureKeyPair;
// // use std::mem::size_of_val;

// // // Helpers to generate credentials and key packages
// // fn generate_credential_with_key(
// //   identity: Vec<u8>,
// //   signature_algorithm: SignatureScheme,
// //   provider: &impl OpenMlsProvider,
// // ) -> (CredentialWithKey, SignatureKeyPair) {
// //   let credential = BasicCredential::new(identity);
// //   let signature_keys =
// //       SignatureKeyPair::new(signature_algorithm).expect("Error generating key pair");
// //   signature_keys
// //       .store(provider.storage())
// //       .expect("Error storing keys");
// //   (
// //       CredentialWithKey {
// //           credential: credential.into(),
// //           signature_key: signature_keys.public().into(),
// //       },
// //       signature_keys,
// //   )
// // }

// // fn generate_key_package(
// //   ciphersuite: Ciphersuite,
// //   provider: &impl OpenMlsProvider,
// //   signer: &SignatureKeyPair,
// //   credential_with_key: CredentialWithKey,
// // ) -> KeyPackageBundle {
// //   KeyPackage::builder()
// //       .build(ciphersuite, provider, signer, credential_with_key)
// //       .unwrap()
// // }

// // fn main() {
// //   let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
// //   let provider = &OpenMlsRustCrypto::default();

// //   // Create credentials for Sasha and Maxim
// //   let (sasha_cred, sasha_signer) = generate_credential_with_key(
// //       b"Sasha".to_vec(),
// //       ciphersuite.signature_algorithm(),
// //       provider,
// //   );
// //   let (maxim_cred, maxim_signer) = generate_credential_with_key(
// //       b"Maxim".to_vec(),
// //       ciphersuite.signature_algorithm(),
// //       provider,
// //   );

// //   // Generate Maxim's key package
// //   let maxim_kp = generate_key_package(ciphersuite, provider, &maxim_signer, maxim_cred);

// //   // Sasha creates a group and adds Maxim
// //   let mut sasha_group = MlsGroup::new(
// //       provider,
// //       &sasha_signer,
// //       &MlsGroupCreateConfig::default(),
// //       sasha_cred,
// //   )
// //   .expect("Group creation failed");

// //   let (_mls_msg, welcome, _group_info) = sasha_group
// //       .add_members(provider, &sasha_signer, &[maxim_kp.key_package().clone()])
// //       .expect("Add members failed");
// //   sasha_group.merge_pending_commit(provider).expect("Merge failed");

// //   // Maxim processes the welcome
// //   let welcome_bytes = welcome
// //       .tls_serialize_detached()
// //       .expect("Failed to serialize welcome");
// //   let mls_message_in = MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
// //       .expect("Failed to deserialize welcome");
// //   let welcome = match mls_message_in.extract() {
// //       MlsMessageBodyIn::Welcome(w) => w,
// //       _ => panic!("Not a Welcome message"),
// //   };

// //   let staged = StagedWelcome::new_from_welcome(
// //       provider,
// //       &MlsGroupJoinConfig::default(),
// //       welcome,
// //       Some(sasha_group.export_ratchet_tree().into()),
// //   )
// //   .unwrap();
// //   let mut maxim_group = staged.into_group(provider).unwrap();

// //   //compute internal meory used for 2 to 100 nodes in the system
// //   //store all the messages recieved in sorted order [msg_id , timesatmp, content]
// //   // compute merkel proof for the messages [use the msg content and timesatmp, the proof should have format [start msg id:<>, end msg id:<> , proof :<>]]
// //   //use this for computing the merkel proof
// //   //send the merkel proff as part of the messages body eg : let message = b"Merkel Proof , start msg id:<>, end msg id:<> , proof :<>";
// //   // now lets calculate the space it requres to store 100 messages, with the timestamp and 
// //   // Maxim sends a message
// //   let message = b"Hello, Sasha, Merkel Tree <ubduwebxuebuebxiewndiewduwenxiwebdiewjedio> dbifbwifnwindqwejbdejbdejbkejefbjednkekbdjewbfjwqefn";
  

// //   // --- after you create the MLS message ---
// // let mls_message_out = maxim_group
// //     .create_message(provider, &maxim_signer, message)
// //     .expect("Message creation failed");

// // // 0) In-memory sizes
// //     println!(
// //         "MlsMessageOut struct size: {} bytes",
// //         //size_of_val(&mls_message_out)
// //         mls_message_out.tls_serialized_len()
// //     );
// //     if let MlsMessageBodyOut::PrivateMessage(private_msg) = mls_message_out.body() {
// //         println!(
// //             "PrivateMessage struct size: {} bytes",
// //             private_msg.tls_serialized_len()
// //         );
// //     }

// // // 1) Full wire size (header + AEAD tag + ciphertext)
// // let wire = mls_message_out
// //     .tls_serialize_detached()
// //     .expect("Message serialization failed");
// // println!("Wire-format size: {} bytes", wire.len());


    
// //   if let MlsMessageBodyOut::PrivateMessage(private_msg) = mls_message_out.body() {
// //     println!(
// //         "MLSCiphertext (AEAD blob) size: {} bytes",
// //         private_msg.tls_serialized_len()
// //     );
// // } else {
// //     panic!("Expected a PrivateMessage");
// // }


// // // 3) Now decrypt & measure plaintext
// // let mli = MlsMessageIn::tls_deserialize(&mut wire.as_slice()).unwrap();
// // let protocol_msg = mli.try_into_protocol_message().unwrap();
// // let processed_msg = sasha_group
// //     .process_message(provider, protocol_msg)
// //     .unwrap();

// // if let ProcessedMessageContent::ApplicationMessage(app_msg) = processed_msg.into_content() {
// //     let pt_len = app_msg.into_bytes().len();
// //     println!("Plaintext size: {} bytes", pt_len);

// //     // 4) Overhead = wire − plaintext
// //     println!("Message overhead on the wire: {} bytes", wire.len().saturating_sub(pt_len));
// // } else {
// //     panic!("Expected application message");
// // }
// // }

// use openmls::{
//   prelude::{*, tls_codec::*},
// };
// use openmls_rust_crypto::OpenMlsRustCrypto;
// use openmls_basic_credential::SignatureKeyPair;
// use std::mem::size_of_val;

// fn generate_credential_with_key(
//   identity: Vec<u8>,
//   signature_algorithm: SignatureScheme,
//   provider: &impl OpenMlsProvider,
// ) -> (CredentialWithKey, SignatureKeyPair) {
//   let credential = BasicCredential::new(identity);
//   let signature_keys =
//       SignatureKeyPair::new(signature_algorithm).expect("Error generating key pair");
//   signature_keys
//       .store(provider.storage())
//       .expect("Error storing keys");
//   (
//       CredentialWithKey {
//           credential: credential.into(),
//           signature_key: signature_keys.public().into(),
//       },
//       signature_keys,
//   )
// }

// fn generate_key_package(
//   ciphersuite: Ciphersuite,
//   provider: &impl OpenMlsProvider,
//   signer: &SignatureKeyPair,
//   credential_with_key: CredentialWithKey,
// ) -> KeyPackageBundle {
//   KeyPackage::builder()
//       .build(ciphersuite, provider, signer, credential_with_key)
//       .unwrap()
// }

// fn compute_merkle_proof_size(num_messages: usize) -> usize {
//   let log_n = (num_messages as f64).log2().ceil() as usize;
//   let hash_size = 32; // SHA-256
//   log_n * hash_size
// }

// fn main() {
//   let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
//   let provider = &OpenMlsRustCrypto::default();

//   let (sasha_cred, sasha_signer) = generate_credential_with_key(
//       b"Sasha".to_vec(),
//       ciphersuite.signature_algorithm(),
//       provider,
//   );
//   let (maxim_cred, maxim_signer) = generate_credential_with_key(
//       b"Maxim".to_vec(),
//       ciphersuite.signature_algorithm(),
//       provider,
//   );

//   let maxim_kp = generate_key_package(ciphersuite, provider, &maxim_signer, maxim_cred);

//   let mut sasha_group = MlsGroup::new(
//       provider,
//       &sasha_signer,
//       &MlsGroupCreateConfig::default(),
//       sasha_cred,
//   )
//   .expect("Group creation failed");

//   let (_mls_msg, welcome, _group_info) = sasha_group
//       .add_members(provider, &sasha_signer, &[maxim_kp.key_package().clone()])
//       .expect("Add members failed");
//   sasha_group.merge_pending_commit(provider).expect("Merge failed");

//   let welcome_bytes = welcome
//       .tls_serialize_detached()
//       .expect("Failed to serialize welcome");
//   let mls_message_in = MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
//       .expect("Failed to deserialize welcome");
//   let welcome = match mls_message_in.extract() {
//       MlsMessageBodyIn::Welcome(w) => w,
//       _ => panic!("Not a Welcome message"),
//   };

//   let staged = StagedWelcome::new_from_welcome(
//       provider,
//       &MlsGroupJoinConfig::default(),
//       welcome,
//       Some(sasha_group.export_ratchet_tree().into()),
//   )
//   .unwrap();
//   let mut maxim_group = staged.into_group(provider).unwrap();

//   // --- Example for n = 100 messages ---

//   let num_messages = 100;
//   let message = b"Hello Sasha. Merkle Proof Msg ID:<1>, End Msg ID:<100>, Proof:<...>";
//   let message_len = message.len();

//   // Send MLS message
//   let mls_message_out = maxim_group
//       .create_message(provider, &maxim_signer, message)
//       .expect("Message creation failed");

//   let wire = mls_message_out
//       .tls_serialize_detached()
//       .expect("Message serialization failed");

//   let mli = MlsMessageIn::tls_deserialize(&mut wire.as_slice()).unwrap();
//   let protocol_msg = mli.try_into_protocol_message().unwrap();
//   let processed_msg = sasha_group
//       .process_message(provider, protocol_msg)
//       .unwrap();

//   if let ProcessedMessageContent::ApplicationMessage(app_msg) = processed_msg.into_content() {
//       let pt_len = app_msg.into_bytes().len();
//       let overhead = wire.len().saturating_sub(pt_len);
//       let proof_size = compute_merkle_proof_size(num_messages);
//       let total_storage = message_len + proof_size;

//       println!("--- Storage Report for {} Messages ---", num_messages);
//       println!("Original plaintext size: {} bytes", pt_len);
//       println!("Merkle proof size: {} bytes", proof_size);
//       println!("Total storage per message (msg + proof): {} bytes", total_storage);
//       println!("Wire-format message size: {} bytes", wire.len());
//       println!("Overhead from MLS encryption: {} bytes", overhead);
//   } else {
//       panic!("Expected application message");
//   }
// }
use openmls::{
  prelude::{*, tls_codec::*},
};
use openmls_rust_crypto::OpenMlsRustCrypto;
use openmls_basic_credential::SignatureKeyPair;
use std::mem::size_of_val;
use std::time::Instant;
use sha2::{Digest, Sha256};

fn generate_credential_with_key(
  identity: Vec<u8>,
  signature_algorithm: SignatureScheme,
  provider: &impl OpenMlsProvider,
) -> (CredentialWithKey, SignatureKeyPair) {
  let credential = BasicCredential::new(identity);
  let signature_keys =
      SignatureKeyPair::new(signature_algorithm).expect("Error generating key pair");
  signature_keys
      .store(provider.storage())
      .expect("Error storing keys");
  (
      CredentialWithKey {
          credential: credential.into(),
          signature_key: signature_keys.public().into(),
      },
      signature_keys,
  )
}

fn generate_key_package(
  ciphersuite: Ciphersuite,
  provider: &impl OpenMlsProvider,
  signer: &SignatureKeyPair,
  credential_with_key: CredentialWithKey,
) -> KeyPackageBundle {
  KeyPackage::builder()
      .build(ciphersuite, provider, signer, credential_with_key)
      .unwrap()
}

/// Compute the Merkle‐proof for leaf `index` in a tree whose leaves are `hashes`.
/// Returns the vector of sibling‐hashes from leaf up to (but not including) the root.
fn compute_merkle_proof(hashes: &[Vec<u8>], index: usize) -> Vec<Vec<u8>> {
  let mut proof = Vec::new();
  let mut idx = index;
  let mut level = hashes.to_vec();

  while level.len() > 1 {
      // build next level
      let mut next = Vec::new();
      for chunk in level.chunks(2) {
          let left = &chunk[0];
          let right = chunk.get(1).unwrap_or(left);
          let mut hasher = Sha256::new();
          hasher.update(left);
          hasher.update(right);
          next.push(hasher.finalize().to_vec());
      }
      // pick sibling
      let sibling = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
      if sibling < level.len() {
          proof.push(level[sibling].clone());
      }
      idx /= 2;
      level = next;
  }

  proof
}

fn main() {
  // -- setup identical to your snippet
  let ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
  let provider = &OpenMlsRustCrypto::default();

  let (sasha_cred, sasha_signer) = generate_credential_with_key(
      b"Sasha".to_vec(),
      ciphersuite.signature_algorithm(),
      provider,
  );

  // start group with Sasha alone
  let mut sasha_group = MlsGroup::new(
      provider,
      &sasha_signer,
      &MlsGroupCreateConfig::default(),
      sasha_cred,
  )
  .expect("Group creation failed");

  // store the raw plaintext messages for Merkle‐tree building
  let mut stored_messages: Vec<Vec<u8>> = Vec::new();

  // print CSV header
  println!("GroupSize,AppSendTime_ns,ProofCompTime_ns,\
PlaintextSize,ProofSize,TotalStorage,WireSize,Overhead,LocalMem");

  // add 100 users one at a time, measure at each step
  for i in 1..=100 {
      // --- add a new member ---
      let id = format!("User{}", i).into_bytes();
      let (cred, signer) = generate_credential_with_key(
          id.clone(),
          ciphersuite.signature_algorithm(),
          provider,
      );
      let kp = generate_key_package(ciphersuite, provider, &signer, cred);
      let (_m, welcome, _gi) = sasha_group
          .add_members(provider, &sasha_signer, &[kp.key_package().clone()])
          .expect("Add members failed");
      sasha_group.merge_pending_commit(provider).expect("Merge failed");

      // (Optionally process welcome here if you want the new user to join fully)

      // --- prepare and send one application message ---
      let message = format!(
          "Hello iteration {} with a bit more payload to vary size.",
          i
      )
      .into_bytes();
      let plaintext_size = message.len();

      let t0 = Instant::now();
      let mls_out = sasha_group
          .create_message(provider, &sasha_signer, &message)
          .expect("Message creation failed");
      let app_ns = t0.elapsed().as_nanos();

      // --- append leaf hash for the Merkle tree ---
      let mut h = Sha256::new();
      h.update(&message);
      let leaf = h.finalize().to_vec();
      stored_messages.push(leaf);

      // --- compute Merkle proof for the last leaf ---
      let t1 = Instant::now();
      let proof = compute_merkle_proof(&stored_messages, stored_messages.len() - 1);
      let proof_ns = t1.elapsed().as_nanos();

      let proof_size: usize = proof.iter().map(|p| p.len()).sum();
      let total_storage = plaintext_size + proof_size;

      // --- serialize to wire and measure ---
      let wire = mls_out
          .tls_serialize_detached()
          .expect("Wire serialization failed");
      let wire_size = wire.len();
      let overhead = wire_size.saturating_sub(plaintext_size);

      // --- approximate local memory for storing all leaves + one proof ---
      let local_mem: usize = stored_messages.iter().map(|l| l.len()).sum::<usize>()
          + proof_size;

      // --- emit CSV row ---
      let group_size = sasha_group.members().count();
      println!(
          "{},{},{},{},{},{},{},{},{}",
          group_size,
          app_ns,
          proof_ns,
          plaintext_size,
          proof_size,
          total_storage,
          wire_size,
          overhead,
          local_mem
      );
  }
}
