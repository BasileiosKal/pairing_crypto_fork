use pairing_crypto::{
    bbs::{
        ciphersuites::{
            bls12_381::KeyPair,
            bls12_381_g1_sha_256::{
                proof_gen as bls12_381_g1_sha_256_proof_gen,
                proof_verify as bls12_381_g1_sha_256_proof_verify,
                sign as bls12_381_g1_sha_256_sign,
                verify as bls12_381_g1_sha_256_verify,
            },
            bls12_381_g1_shake_256::{
                proof_gen as bls12_381_g1_shake_256_proof_gen,
                proof_verify as bls12_381_g1_shake_256_proof_verify,
                sign as bls12_381_g1_shake_256_sign,
                verify as bls12_381_g1_shake_256_verify,
            },
        },
        BbsProofGenRequest,
        BbsProofGenRevealMessageRequest,
        BbsProofVerifyRequest,
        BbsSignRequest,
        BbsVerifyRequest,
    },
    Error,
};
use rand_core::OsRng;

const KEY_GEN_SEED: &[u8; 32] = b"not_A_random_seed_at_Allllllllll";

const TEST_KEY_INFOS: [&[u8]; 7] = [
    b"",
    b"abc",
    b"abcdefgh",
    b"abcdefghijklmnopqrstuvwxyz",
    b"qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq",
    b"12345678901234567890123456789012345678901234567890",
    b"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik,9ol.0p;/",
];
const TEST_CLAIMS: [&[u8]; 6] = [
    b"first_name",
    b"surname",
    b"date_of_birth",
    b"father",
    b"mother",
    b"credential_id",
];

const TEST_PRESENTATION_HEADER: &[u8; 24] = b"test-presentation-header";

const EXPECTED_SIGNATURES_SHAKE_256: [&str; 7] = [
    "8a8745e0efe832bea36e35cd9fa60cf93aced4cf6429d6a414a0e4b5ae20f6a46dd6e1e3e8c3b681d41d831b6d78523421d26c306ea82cb571ae883b3328b43dbc864508f214b5e423ffb4a0da9c3dbe2affd962c897033ee7939faa1c2bd104824b6e519071bbe645473660604f2ed4",
    "814764df46a6f7085c3ebd6323867287c17a4b53c9281f7765a48cefc16579fa4210fdfe0d7ffa8556af86e5c71f448f504c8f62051ad6054f2deddeb9ac4600302aaf82ceb9bc314c861c4c3af121951a358a951abcda328b14369adc870f3141996299d37a32f3079582a09ee1f531",
    "b254a9e013aa1de59f969ab542c578431ac5a370c65e6f2195bdd3168e3e6ff5bfecfdc7287a8a4f58675b184f37931224e45723371c6c8c047e68ca173ee7f6c4bc1fe6993ee55ec9b0303726832c3456281680a23ece89a15bbf04fcf77872b6791b5cf69dbb88b69e57141e1884ae",
    "870312b7f874665ee8139a779c62ac8c8875ecc03748b5ca94e8383b5faec6e8daf4df860180523dbfa360a3a437f0dd41b3d6e3baae73d7c577a7fee1535a2f31a00fcff8570ba0b0df1fac664e69c303b1b58b205875acb154de98ad023a1a15039238669204a2cd86b54f0df3c038",
    "8436aa432cd7942fee8575261be93412c83ac91fad4a0e3a96327903b4bdc60e739be96a2309f9fa0b484e00401712e2188ea2fb3b84c902fcbf4e62f79beb94f2cdaa8449e18cb1838445a7c311790a6c22aa58cda99dc1ce5e2f773b7fa33da327ead5440e010ce63dfa359f72ba02",
    "aa0f3b5913f6562d049299baff70251c018948df48e043aacc22d523179438f13dca3741e65ca7d4201812ab26f151487041a35c47ac85140f5dc4c372e118b783979c019d2c53ee9c607b5e0aedbaf714d1b26997a70578900f84fa2566b6972d9bb9e66207c11c47d138b0a20dccfd",
    "b322effd49a97c3fd78aaabd6cafaceb81bda50160a22fd72170b58c28a41c1edec2fbdd46344e03deccf3e6a9dc91e023e4ec6a6e3b5432d2c1bd47b8d8f5c8eb0131eb053f9fefa825f537df6c3c8e584a338054c69da7beddd52f7f013340d993d35a569e6f7edd312eee0d745a6c",
];

const EXPECTED_SIGNATURES_SHA_256: [&str; 7] = [
    "86585eb6927fba4eb4092189c36ec198595f5b662968716a8af2dd8fdcf59940fc14db22b6cba46caa80c476e2d324d955449d722e1831244634920af6999093f69b99516994ab81eec1f285a55da7cd4c486c02db54489eed3628c74f1732c1b793153b3aebc2d084b220dbdcad4634",
    "a722771f35df53ade4bd9721beb4ea75201d8f419a25066c1b3aa3ea2c6c5c33483ba982f6d878ac7ec28c67f09d87fd216846789b47fcbcda8829b63d446d17ca16edb8157557b3008ba818be679f2118ef82a5678d1bc095060d7b7eddb161d81cb28dd64a2b8cc0d8ef0fd77099e7",
    "992f5f265673a45a13b5072531591f093d3bca97e2dfe790e40bf2f4896ac567f2fe61df2c7119890f5de34c8c9759745cd2563977792546889a5c6f4537b4b2c9c6d5cec3582c3520337376da37d3fc3d16fc583499c974317bb8a193ecf910e18bccf61cd8a1f704d6c2fc30ff3070",
    "8abc343c60524e4da89840cccd348b5039e33df8c178de9a0598d3cf8f3f20a884472768b3138e576529bba79e2bbd6a1be88da72a3fe8a8a44de428e9ed834fdc5635e25ab09d33b8db416b1be0cd9e04c858e016ad4e3b73e2a0a6f92dd2dea05bd2a7432eb07f14be53c426844b45",
    "a07316159970a9fc19a6dc01d03c14aaf2c2169d598156b995d716f3eaf3946a840bcf5470885973a6dec548048787e828c43f205f92cd6d093ecf43287373b7c8e628269f3162c77e4d96cbbffaae3325a243139ca14a775d81bd70406bec184c91938e2b543d94d51d30587f91b663",
    "ad9ed01805ed3ec0f3b84e02c3a1fbbb6a5902190d3f5d2bfe1c2ce022c891ddfd75796444de27f3d6d1cc7a2efbd97f05829251d69f94b84140301fcbe158d338ed3ec28cadff58fa7bae9181635be04b306231f14ab0e67b106d6710c6b5aa85d279e069ee20c40b878aa690b34ba0",
    "958bec9627d095bdcad0deed62b87f0c26ce6af01685d1dee2534ff6714b0287eeb122f25a56fd5a62ee81f8629bef2c3f563e6aad41178fa5217ac9be381597627535f4405bf9cda9a2bda99d5cc6532f3d83469431a3cb3fecd327972dff8cde43db1dd0ff01500251bffe131aa2cd",
];

const TEST_HEADER: &[u8; 16] = b"some_app_context";

macro_rules! sign_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident, $signature_test_vector:ident) => {
        let header = TEST_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        for i in 0..TEST_KEY_INFOS.len() {
            let (secret_key, public_key) =
                KeyPair::new(KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFOS[i]))
                    .map(|key_pair| {
                        (
                            key_pair.secret_key.to_bytes(),
                            key_pair.public_key.to_octets(),
                        )
                    })
                    .expect("key generation failed");

            let signature = $sign_fn(&BbsSignRequest {
                secret_key: &secret_key,
                public_key: &public_key,
                header: Some(header),
                messages: Some(messages),
            })
            .expect("signature generation failed");

            let expected_signature = hex::decode($signature_test_vector[i])
                .expect("hex decoding failed");
            assert_eq!(signature.to_vec(), expected_signature);
            // println!("{:?},", hex::encode(signature));

            assert_eq!(
                $verify_fn(&BbsVerifyRequest {
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(messages),
                    signature: &signature,
                })
                .expect("error during signature verification"),
                true
            );
        }
    };
}

#[allow(unused)]
#[test]
fn sign_verify_e2e_nominal() {
    sign_verify_e2e_nominal!(
        bls12_381_g1_shake_256_sign,
        bls12_381_g1_shake_256_verify,
        EXPECTED_SIGNATURES_SHAKE_256
    );

    sign_verify_e2e_nominal!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        EXPECTED_SIGNATURES_SHA_256
    );
}

macro_rules! proof_gen_verify_e2e_nominal {
    ($sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident, $proof_verify_fn:ident) => {
        let header = TEST_HEADER.as_ref();
        let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        for i in 0..TEST_KEY_INFOS.len() {
            let (secret_key, public_key) =
                KeyPair::new(KEY_GEN_SEED.as_ref(), Some(TEST_KEY_INFOS[i]))
                    .map(|key_pair| {
                        (
                            key_pair.secret_key.to_bytes(),
                            key_pair.public_key.to_octets(),
                        )
                    })
                    .expect("key generation failed");

            let signature = $sign_fn(&BbsSignRequest {
                secret_key: &secret_key,
                public_key: &public_key,
                header: Some(header),
                messages: Some(messages),
            })
            .expect("signature generation failed");

            assert_eq!(
                $verify_fn(&BbsVerifyRequest {
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(messages),
                    signature: &signature,
                })
                .expect("error during signature verification"),
                true
            );

            // Start with all hidden messages
            let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
                messages
                    .iter()
                    .map(|value| BbsProofGenRevealMessageRequest {
                        reveal: false,
                        value: value.clone(),
                    })
                    .collect();

            // Reveal 1 message at a time
            for j in 0..proof_messages.len() {
                let proof = &$proof_gen_fn(&BbsProofGenRequest {
                    public_key: &public_key,
                    header: Some(header),
                    messages: Some(&proof_messages),
                    signature: &signature,
                    presentation_header: Some(presentation_header),
                    verify_signature: None,
                })
                .expect("proof generation failed");

                let mut revealed_msgs = Vec::new();
                for k in 0..j {
                    revealed_msgs.push((k as usize, TEST_CLAIMS[k]));
                }

                assert_eq!(
                    $proof_verify_fn(&BbsProofVerifyRequest {
                        public_key: &public_key,
                        header: Some(header),
                        presentation_header: Some(presentation_header),
                        proof: &proof,
                        total_message_count: messages.len(),
                        messages: Some(revealed_msgs.as_slice()),
                    })
                    .expect("proof verification failed"),
                    true
                );
                proof_messages[j].reveal = true;
            }
        }
    };
}

#[test]
fn proof_gen_verify_e2e_nominal() {
    proof_gen_verify_e2e_nominal!(
        bls12_381_g1_shake_256_sign,
        bls12_381_g1_shake_256_verify,
        bls12_381_g1_shake_256_proof_gen,
        bls12_381_g1_shake_256_proof_verify
    );

    proof_gen_verify_e2e_nominal!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        bls12_381_g1_sha_256_proof_gen,
        bls12_381_g1_sha_256_proof_verify
    );
}

macro_rules! proof_gen_failure_message_modified {
    ($sign_fn:ident, $verify_fn:ident, $proof_gen_fn:ident) => {
        let num_disclosed_messages = 4;
        let header = TEST_HEADER.as_ref();
        let presentation_header = TEST_PRESENTATION_HEADER.as_ref();
        let messages = &TEST_CLAIMS;

        let (secret_key, public_key) = KeyPair::random(&mut OsRng, None)
            .map(|key_pair| {
                (
                    key_pair.secret_key.to_bytes(),
                    key_pair.public_key.to_octets(),
                )
            })
            .expect("key generation failed");

        let signature = $sign_fn(&BbsSignRequest {
            secret_key: &secret_key,
            public_key: &public_key,
            header: Some(header),
            messages: Some(messages),
        })
        .expect("signature generation failed");

        assert_eq!(
            $verify_fn(&BbsVerifyRequest {
                public_key: &public_key,
                header: Some(header),
                messages: Some(messages),
                signature: &signature,
            })
            .expect("error during signature verification"),
            true
        );

        // Start with all hidden messages
        let mut proof_messages: Vec<BbsProofGenRevealMessageRequest<_>> =
            messages
                .iter()
                .map(|value| BbsProofGenRevealMessageRequest {
                    reveal: false,
                    value: value.clone(),
                })
                .collect();

        let mut revealed_msgs = Vec::new();
        for i in 0..num_disclosed_messages {
            proof_messages[i].reveal = true;
            revealed_msgs.push((i as usize, TEST_CLAIMS[i].to_vec()));
        }

        // Modify one of the messages
        proof_messages[1].value = &[0xA; 50];

        // Proof-gen fails with tampered message when we pass `true` value for
        // `verify_signature`.
        let result = $proof_gen_fn(&BbsProofGenRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(&proof_messages),
            signature: &signature,
            presentation_header: Some(presentation_header),
            verify_signature: Some(true),
        });
        assert_eq!(result, Err(Error::SignatureVerification));

        // Proof-gen succeeds with tampered message when we pass `false`value
        // for `verify_signature`.
        $proof_gen_fn(&BbsProofGenRequest {
            public_key: &public_key,
            header: Some(header),
            messages: Some(&proof_messages),
            signature: &signature,
            presentation_header: Some(presentation_header),
            verify_signature: Some(false),
        })
        .expect("proof should be generated for tampered messages");
    };
}

#[test]
fn proof_gen_failure_message_modified() {
    proof_gen_failure_message_modified!(
        bls12_381_g1_shake_256_sign,
        bls12_381_g1_shake_256_verify,
        bls12_381_g1_shake_256_proof_gen
    );

    proof_gen_failure_message_modified!(
        bls12_381_g1_sha_256_sign,
        bls12_381_g1_sha_256_verify,
        bls12_381_g1_sha_256_proof_gen
    );
}
