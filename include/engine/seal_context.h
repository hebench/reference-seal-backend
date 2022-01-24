
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ostream>
#include <string>

#include <seal/seal.h>

#include "hebench/api_bridge/cpp/hebench.hpp"

class SEALContextWrapper
{
public:
    HEBERROR_DECLARE_CLASS_NAME(SEALContextWrapper)
    SEALContextWrapper(const SEALContextWrapper &) = delete;
    SEALContextWrapper &operator=(const SEALContextWrapper &) = delete;

public:
    typedef std::shared_ptr<SEALContextWrapper> Ptr;

    /**
     * @brief CKKS constructor
     * @param[in] poly_modulus_degree
     * @param[in] num_coeff_moduli Min multiplicative depth.
     * @param[in] coeff_moduli_bits Bits for coefficient moduli. Usually equals scale bits.
     * @param[in] scale_bits Scale is going to be 2^scale_bits.
     * @param[in] sec_level Security level to enforce.
     */
    static SEALContextWrapper::Ptr createCKKSContext(std::size_t poly_modulus_degree,
                                                     std::size_t num_coeff_moduli,
                                                     int coeff_moduli_bits,
                                                     int scale_bits,
                                                     seal::sec_level_type sec_level = seal::sec_level_type::tc128);

    /**
     * @brief BFV constructor
     * @param[in] poly_modulus_degree
     * @param[in] num_coeff_moduli Min multiplicative depth.
     * @param[in] coeff_moduli_bits Min bits for coefficient moduli.
     * @param[in] plaintext_modulus_bits Bits for plaintext modulus.
     * @param[in] sec_level Security level to enforce.
     */
    static SEALContextWrapper::Ptr createBFVContext(std::size_t poly_modulus_degree,
                                                    std::size_t num_coeff_moduli,
                                                    int coeff_moduli_bits,
                                                    int plaintext_modulus_bits     = 20,
                                                    seal::sec_level_type sec_level = seal::sec_level_type::tc128);

    seal::Ciphertext encrypt(const seal::Plaintext &plain) const;
    std::vector<seal::Ciphertext> encrypt(const std::vector<seal::Plaintext> &plain) const;
    void decrypt(const seal::Ciphertext &cipher, seal::Plaintext &plain);
    seal::Plaintext decrypt(const seal::Ciphertext &cipher);
    std::vector<seal::Plaintext> decrypt(const std::vector<seal::Ciphertext> &cipher);

    seal::SEALContext *context() { return m_context.get(); }
    const seal::SEALContext *context() const { return m_context.get(); }
    const seal::PublicKey &publicKey() const { return m_public_key; }
    const seal::RelinKeys &relinKeys() const { return m_relin_keys; }
    const seal::GaloisKeys &galoisKeys() const { return m_galois_keys; }
    const seal::Encryptor *encryptor() const { return m_encryptor.get(); }
    const seal::Evaluator *evaluator() const { return m_evaluator.get(); }
    seal::CKKSEncoder *CKKSEncoder();
    seal::BatchEncoder *BFVEncoder();
    seal::scheme_type scheme() const { return m_scheme; }
    double scale() const { return m_scale; }
    int scaleBits() const { return m_scale_bits; }

    void printContextInfo(std::ostream &os, const std::string &preamble = std::string());

    void matchLevel(seal::Ciphertext &a, seal::Ciphertext &b) const;
    seal::Ciphertext evaluatePolynomial(seal::Ciphertext &cipher_input,
                                        std::vector<seal::Plaintext> &plain_coefficients);

public:
    // BFV
    seal::Plaintext encodeVector(const std::vector<std::int64_t> &values);
    seal::Ciphertext accumulateBFV(const seal::Ciphertext &cipher, std::size_t count);

public:
    // CKKS
    seal::Plaintext encodeVector(const std::vector<double> &values);
    seal::Ciphertext accumulateCKKS(const seal::Ciphertext &cipher, std::size_t count);
    seal::Ciphertext collapseCKKS(const std::vector<seal::Ciphertext> &ciphers, bool do_rotate = true, int num_threads = 0);

protected:
    SEALContextWrapper();
    void createKeysAndEncryptors();
    virtual void initCKKS(std::size_t poly_modulus_degree, std::size_t num_coeff_moduli,
                          int coeff_moduli_bits, int scale_bits, seal::sec_level_type sec_level);
    virtual void initBFV(std::size_t poly_modulus_degree, std::size_t num_coeff_moduli,
                         int coeff_moduli_bits, int plaintext_modulus_bits, seal::sec_level_type sec_level);

private:
    std::shared_ptr<seal::SEALContext> m_context;
    std::unique_ptr<seal::KeyGenerator> m_keygen;
    seal::PublicKey m_public_key;
    seal::SecretKey m_secret_key;
    seal::RelinKeys m_relin_keys;
    seal::GaloisKeys m_galois_keys;
    std::unique_ptr<seal::Encryptor> m_encryptor;
    std::unique_ptr<seal::Evaluator> m_evaluator;
    std::unique_ptr<seal::Decryptor> m_decryptor;
    std::unique_ptr<seal::CKKSEncoder> m_ckks_encoder;
    std::unique_ptr<seal::BatchEncoder> m_bfv_batch_encoder;
    seal::scheme_type m_scheme;
    int m_scale_bits;
    double m_scale;
};
