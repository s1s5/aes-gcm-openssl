use core::fmt;

use aead::Payload;
use generic_array::{
    GenericArray,
    typenum::{B0, B1, U16, UInt, UTerm},
};
use openssl::symm::{Cipher, Crypter, Mode};

pub mod aead {
    pub use generic_array;

    pub struct Aead {}

    pub struct Payload<'msg, 'aad> {
        pub msg: &'msg [u8],
        pub aad: &'aad [u8],
    }
}

pub type U12 = UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("aead::Error")
    }
}

impl std::error::Error for Error {}

pub struct KeyInit;

// pub type Nonce<NonceSize> = GenericArray<u8, NonceSize>;
pub struct Nonce {
    data: Vec<u8>,
}

impl Nonce {
    pub fn from_slice(data: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
        }
    }
}

#[derive(Clone)]
pub struct Aes128Gcm {
    key: Vec<u8>,
    cipher: Cipher,
}

impl Aes128Gcm {
    pub fn new(key: &GenericArray<u8, U16>) -> Self {
        Self {
            key: key.iter().copied().collect(),
            cipher: Cipher::aes_128_gcm(),
        }
    }
    pub fn encrypt(&self, nonce: Nonce, payload: Payload) -> Result<Vec<u8>, Error> {
        // let mut buffer = Vec::with_capacity(payload.msg.len() + U16::to_usize()); // Self::TagSize::to_usize());
        // buffer.extend_from_slice(payload.msg);
        // // let tag = self.encrypt_in_place_detached(nonce, associated_data, buffer.as_mut())?;
        // buffer.extend_from_slice(tag.as_slice())?;
        // todo!()
        println!("create encrypter");
        let mut encrypter = Crypter::new(self.cipher, Mode::Encrypt, &self.key, Some(&nonce.data))
            .map_err(|_| Error)?;
        println!("add_update");
        encrypter.aad_update(payload.aad).map_err(|_| Error)?;

        println!("ciphertext");
        // 出力バッファ（暗号文）
        let mut ciphertext = vec![0; payload.msg.len() + self.cipher.block_size()];
        println!("encrypter.update");
        let mut count = encrypter
            .update(payload.msg, &mut ciphertext)
            .map_err(|_| Error)?;
        println!("finalize");
        count += encrypter
            .finalize(&mut ciphertext[count..])
            .map_err(|_| Error)?;
        println!("struncate");
        ciphertext.truncate(count);

        // 認証タグの取得（16バイト）
        let mut tag = [0u8; 16];
        println!("get_tag");
        encrypter.get_tag(&mut tag).map_err(|_| Error)?;

        println!("complete");
        ciphertext.extend_from_slice(&tag);

        Ok(ciphertext)
    }

    pub fn decrypt(&self, nonce: Nonce, payload: Payload) -> Result<Vec<u8>, Error> {
        let ciphertext_len = payload.msg.len() - 16;
        let (ciphertext, tag) = payload.msg.split_at(ciphertext_len);

        let cipher = Cipher::aes_128_gcm();
        let mut decrypter =
            Crypter::new(cipher, Mode::Decrypt, &self.key, Some(&nonce.data)).unwrap();

        // 認証タグを設定（ここが重要！）
        decrypter.set_tag(tag).unwrap();

        // AADも同じものをセット（してないと復号失敗する）
        decrypter.aad_update(payload.aad).unwrap();

        let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
        let mut count = decrypter.update(ciphertext, &mut plaintext).unwrap();
        count += decrypter.finalize(&mut plaintext[count..]).unwrap();
        plaintext.truncate(count);

        Ok(plaintext)
    }
}

// fn main() {
//     // AES-128-GCM の鍵（16バイト）とIV（12バイト）
//     let key = b"0123456789abcdef";
//     let iv = b"unique_iv_123"; // 12バイト推奨（GCM標準）

//     let key =&hex!("3c1c2aae3954d6f645ce2a697a4f3af8");
//     let iv  = &hex!("04b54f6447ebbcfbda57445a");

//     // 平文データ
//     let plaintext = b"Hello, Rust + AES-128-GCM!";
//     let plaintext =  &hex!("f73e226b50a75558a389ccd738");

//     // 追加認証データ（任意）
//     let aad = b"extra-data";
//     let aad = &hex!("e7a9d5c8328278311dca3e84da2bf0f573198d4f");

//     // 暗号器のセットアップ
//     let cipher = Cipher::aes_128_gcm();
//     let mut encrypter = Crypter::new(cipher, Mode::Encrypt, key, Some(iv)).unwrap();
//     encrypter.aad_update(aad).unwrap();

//     // 出力バッファ（暗号文）
//     let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
//     let mut count = encrypter.update(plaintext, &mut ciphertext).unwrap();
//     count += encrypter.finalize(&mut ciphertext[count..]).unwrap();
//     ciphertext.truncate(count);

//     // 認証タグの取得（16バイト）
//     let mut tag = [0u8; 16];
//     encrypter.get_tag(&mut tag).unwrap();

//     println!("Ciphertext: {:x?}", ciphertext);
//     println!("Auth Tag  : {:x?}", tag);
// }

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[derive(Debug)]
    pub struct TestVector<K: 'static> {
        pub key: &'static K,
        pub nonce: &'static [u8; 12],
        pub aad: &'static [u8],
        pub plaintext: &'static [u8],
        pub ciphertext: &'static [u8],
        pub tag: &'static [u8; 16],
    }

    #[macro_export]
    macro_rules! tests {
        ($aead:ty, $vectors:expr) => {
            #[test]
            fn encrypt() {
                for vector in $vectors {
                    let key = GenericArray::from_slice(vector.key);
                    let nonce = Nonce::from_slice(vector.nonce);
                    let payload = Payload {
                        msg: vector.plaintext,
                        aad: vector.aad,
                    };

                    let cipher = <$aead>::new(key);
                    let ciphertext = cipher.encrypt(nonce, payload).unwrap();
                    let (ct, tag) = ciphertext.split_at(ciphertext.len() - 16);
                    assert_eq!(vector.ciphertext, ct);
                    assert_eq!(vector.tag, tag);
                }
            }

            #[test]
            fn decrypt() {
                for vector in $vectors {
                    let key = GenericArray::from_slice(vector.key);
                    let nonce = Nonce::from_slice(vector.nonce);
                    let mut ciphertext = Vec::from(vector.ciphertext);
                    ciphertext.extend_from_slice(vector.tag);

                    let payload = Payload {
                        msg: &ciphertext,
                        aad: vector.aad,
                    };

                    let cipher = <$aead>::new(key);
                    let plaintext = cipher.decrypt(nonce, payload).unwrap();

                    assert_eq!(vector.plaintext, plaintext.as_slice());
                }
            }
        };
    }
    const TEST_VECTORS: &[TestVector<[u8; 16]>] = &[
        TestVector {
            key: &hex!("11754cd72aec309bf52f7687212e8957"),
            nonce: &hex!("3c819d9a9bed087615030b65"),
            plaintext: &hex!(""),
            aad: &hex!(""),
            ciphertext: &hex!(""),
            tag: &hex!("250327c674aaf477aef2675748cf6971"),
        },
        TestVector {
            key: &hex!("ca47248ac0b6f8372a97ac43508308ed"),
            nonce: &hex!("ffd2b598feabc9019262d2be"),
            plaintext: &hex!(""),
            aad: &hex!(""),
            ciphertext: &hex!(""),
            tag: &hex!("60d20404af527d248d893ae495707d1a"),
        },
    ];
    tests!(Aes128Gcm, TEST_VECTORS);
}
