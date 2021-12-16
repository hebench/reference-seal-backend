
// Copyright (C) 2021 Intel Corporation
// SPDX-License-Identifier: Apache-2.0

#include <cassert>
#include <new>
#include <stdexcept>

#include "engine/seal_context.h"
#include "engine/seal_types.h"

//-----------------------
// class SEALContextWrapper
//-----------------------

SEALContextWrapper::Ptr SEALContextWrapper::createCKKSContext(std::size_t poly_modulus_degree,
                                                              std::size_t num_coeff_moduli,
                                                              int coeff_moduli_bits,
                                                              int scale_bits,
                                                              seal::sec_level_type sec_level)
{
    SEALContextWrapper::Ptr retval = SEALContextWrapper::Ptr(new SEALContextWrapper());
    retval->initCKKS(poly_modulus_degree, num_coeff_moduli,
                     coeff_moduli_bits, scale_bits, sec_level);
    return retval;
}

SEALContextWrapper::Ptr SEALContextWrapper::createBFVContext(std::size_t poly_modulus_degree,
                                                             std::size_t num_coeff_moduli,
                                                             int coeff_moduli_bits,
                                                             int plaintext_modulus_bits,
                                                             seal::sec_level_type sec_level)
{
    SEALContextWrapper::Ptr retval = SEALContextWrapper::Ptr(new SEALContextWrapper());
    retval->initBFV(poly_modulus_degree, num_coeff_moduli, coeff_moduli_bits,
                    plaintext_modulus_bits, sec_level);
    return retval;
}

SEALContextWrapper::SEALContextWrapper() :
    m_scheme(seal::scheme_type::none), m_scale_bits(0), m_scale(1.0)
{
}

void SEALContextWrapper::createKeysAndEncryptors()
{
    assert(m_context);
    m_keygen = std::unique_ptr<seal::KeyGenerator>(new seal::KeyGenerator(*m_context));
    m_keygen->create_public_key(m_public_key);

    m_secret_key = m_keygen->secret_key();
    m_keygen->create_relin_keys(m_relin_keys);

    m_encryptor = std::unique_ptr<seal::Encryptor>(new seal::Encryptor(*m_context, m_public_key));
    m_evaluator = std::unique_ptr<seal::Evaluator>(new seal::Evaluator(*m_context));
    m_decryptor = std::unique_ptr<seal::Decryptor>(new seal::Decryptor(*m_context, m_secret_key));

    if (m_scheme == seal::scheme_type::ckks)
    {
        m_bfv_batch_encoder.reset();
        m_ckks_encoder = std::unique_ptr<seal::CKKSEncoder>(new seal::CKKSEncoder(*m_context));
    }
    else if (m_scheme == seal::scheme_type::bfv)
    {
        m_ckks_encoder.reset();
        m_bfv_batch_encoder = std::unique_ptr<seal::BatchEncoder>(new seal::BatchEncoder(*m_context));
    }
    m_keygen->create_galois_keys(m_galois_keys);
}

void SEALContextWrapper::initCKKS(std::size_t poly_modulus_degree, std::size_t num_coeff_moduli,
                                  int coeff_moduli_bits, int scale_bits, seal::sec_level_type sec_level)
{
    // CKKS

    try
    {
        std::vector<int> coeff_modulus = { 60 };
        for (std::size_t i = 1; i < num_coeff_moduli; ++i)
            coeff_modulus.push_back(coeff_moduli_bits);
        coeff_modulus.push_back(60);
        m_scale_bits = (scale_bits < 0 ? 0 : scale_bits);
        m_scale      = (m_scale_bits == 0 ? 1.0 : std::pow(2.0, m_scale_bits));

        m_scheme = seal::scheme_type::ckks;
        seal::EncryptionParameters parameters(seal::scheme_type::ckks);
        parameters.set_poly_modulus_degree(poly_modulus_degree);
        parameters.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));
        m_context = std::make_shared<seal::SEALContext>(parameters, true, sec_level);

        createKeysAndEncryptors();
    }
    catch (std::exception &ex)
    {
        throw hebench::cpp::HEBenchError(ex.what(), HEBSEAL_ECODE_SEAL_ERROR);
    }
}

void SEALContextWrapper::initBFV(std::size_t poly_modulus_degree, std::size_t num_coeff_moduli,
                                 int coeff_moduli_bits, int plaintext_modulus_bits, seal::sec_level_type sec_level)
{
    // BFV

    try
    {
        std::vector<int> coeff_modulus = { 60 };
        for (std::size_t i = 1; i < num_coeff_moduli; ++i)
            coeff_modulus.push_back(coeff_moduli_bits);
        coeff_modulus.push_back(60);
        m_scale_bits = 0;
        m_scale      = 1.0;

        m_scheme = seal::scheme_type::bfv;
        seal::EncryptionParameters parameters(seal::scheme_type::bfv);
        parameters.set_poly_modulus_degree(poly_modulus_degree);
        parameters.set_coeff_modulus(seal::CoeffModulus::Create(poly_modulus_degree, coeff_modulus));
        parameters.set_plain_modulus(seal::PlainModulus::Batching(poly_modulus_degree, plaintext_modulus_bits));
        m_context = std::make_shared<seal::SEALContext>(parameters, true, sec_level);

        createKeysAndEncryptors();
    }
    catch (std::exception &ex)
    {
        throw hebench::cpp::HEBenchError(ex.what(), HEBSEAL_ECODE_SEAL_ERROR);
    }
}

seal::CKKSEncoder *SEALContextWrapper::CKKSEncoder()
{
    if (scheme() != seal::scheme_type::ckks || !m_ckks_encoder)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Requested CKKS encoder from non-CKKS SEAL context."),
                                         HEBENCH_ECODE_CRITICAL_ERROR);
    return m_ckks_encoder.get();
}

seal::BatchEncoder *SEALContextWrapper::BFVEncoder()
{
    if (scheme() != seal::scheme_type::bfv || !m_bfv_batch_encoder)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Requested BFV encoder from non-BFV SEAL context."),
                                         HEBENCH_ECODE_CRITICAL_ERROR);
    return m_bfv_batch_encoder.get();
}

seal::Ciphertext SEALContextWrapper::encrypt(const seal::Plaintext &plain) const
{
    seal::Ciphertext cipher;
    encryptor()->encrypt(plain, cipher);
    return cipher;
}

std::vector<seal::Ciphertext> SEALContextWrapper::encrypt(const std::vector<seal::Plaintext> &plain) const
{
    std::vector<seal::Ciphertext> retval(plain.size());
    for (std::size_t i = 0; i < plain.size(); ++i)
        encryptor()->encrypt(plain[i], retval[i]);
    return retval;
}

void SEALContextWrapper::decrypt(const seal::Ciphertext &cipher, seal::Plaintext &plain)
{
    try
    {
        m_decryptor->decrypt(cipher, plain);
    }
    catch (std::exception &ex)
    {
        throw hebench::cpp::HEBenchError(ex.what(), HEBSEAL_ECODE_SEAL_ERROR);
    }
}

seal::Plaintext SEALContextWrapper::decrypt(const seal::Ciphertext &cipher)
{
    seal::Plaintext retval;
    decrypt(cipher, retval);
    return retval;
}

std::vector<seal::Plaintext> SEALContextWrapper::decrypt(const std::vector<seal::Ciphertext> &cipher)
{
    std::vector<seal::Plaintext> retval(cipher.size());
    for (std::size_t i = 0; i < cipher.size(); ++i)
        decrypt(cipher[i], retval[i]);
    return retval;
}

void SEALContextWrapper::printContextInfo(std::ostream &os, const std::string &preamble)
{
    auto p_context_data            = context()->first_context_data();
    std::size_t context_data_count = 1;
    while (p_context_data)
    {
        const seal::SEALContext::ContextData &context_data = *p_context_data;
        const seal::EncryptionParameters &params           = context_data.parms();
        const seal::EncryptionParameterQualifiers &cdq     = context_data.qualifiers();

        os << std::endl
           << "Context, " << context_data_count << std::endl
           << preamble << "Scheme, ";
        switch (params.scheme())
        {
        case seal::scheme_type::bfv:
            os << "BFV";
            break;
        case seal::scheme_type::ckks:
            os << "CKKS";
            break;
        case seal::scheme_type::none:
            os << "none";
            break;
        default:
            os << "unknown";
            break;
        }
        os << std::endl
           << preamble << "Security level standard, ";
        switch (cdq.sec_level)
        {
        case seal::sec_level_type::tc128:
            os << "128 bits";
            break;
        case seal::sec_level_type::tc192:
            os << "192 bits";
            break;
        case seal::sec_level_type::tc256:
            os << "256 bits";
            break;
        case seal::sec_level_type::none:
            os << "none";
            break;
        default:
            os << "unknown";
            break;
        }
        os << std::endl
           << preamble << "Poly modulus degree, " << params.poly_modulus_degree() << std::endl
           << preamble << "Plain modulus, " << params.plain_modulus().value() << std::endl
           << preamble << ", Bit count, " << params.plain_modulus().bit_count() << std::endl
           << preamble << "Coefficient Moduli count, " << params.coeff_modulus().size() << std::endl
           << preamble << "";
        for (std::uint64_t i = 0; i < params.coeff_modulus().size(); ++i)
            os << ", " << params.coeff_modulus()[i].value();
        os << std::endl
           << preamble << "";
        for (std::uint64_t i = 0; i < params.coeff_modulus().size(); ++i)
            os << ", " << params.coeff_modulus()[i].bit_count();
        os << std::endl
           << preamble << "Total bits in coefficient modulus: " << context_data.total_coeff_modulus_bit_count() << std::endl;

        ++context_data_count;
        p_context_data = p_context_data->next_context_data();
    } // end while
}

void SEALContextWrapper::matchLevel(seal::Ciphertext &a, seal::Ciphertext &b) const
{
    int a_level = context()->get_context_data(a.parms_id())->chain_index();
    int b_level = context()->get_context_data(b.parms_id())->chain_index();
    if (a_level > b_level)
        evaluator()->mod_switch_to_inplace(a, b.parms_id());
    else if (a_level < b_level)
        evaluator()->mod_switch_to_inplace(b, a.parms_id());
}

seal::Plaintext SEALContextWrapper::encodeVector(const std::vector<double> &values)
{
    std::size_t slot_count = CKKSEncoder()->slot_count();
    if (values.size() > slot_count)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Not enough slots available to create packed plaintext"),
                                         HEBENCH_ECODE_INVALID_ARGS);

    seal::Plaintext plain1;
    CKKSEncoder()->encode(values, scale(), plain1);
    return plain1;
}

seal::Plaintext SEALContextWrapper::encodeVector(const std::vector<std::int64_t> &values)
{
    std::size_t slot_count = BFVEncoder()->slot_count();
    if (values.size() > slot_count)
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Not enough slots available to create packed plaintext"),
                                         HEBENCH_ECODE_INVALID_ARGS);

    seal::Plaintext plain1;
    BFVEncoder()->encode(values, plain1);
    return plain1;
}

seal::Ciphertext SEALContextWrapper::accumulateBFV(const seal::Ciphertext &cipher, std::size_t count)
{
    seal::Ciphertext retval;
    if (count > 0)
    {
        retval                         = cipher;
        std::size_t row_adjusted_count = (count > (BFVEncoder()->slot_count() / 2)) ? BFVEncoder()->slot_count() / 2 : count;
        auto rotations_required        = seal::util::get_significant_bit_count(row_adjusted_count);
        if (static_cast<decltype(row_adjusted_count)>(1 << (rotations_required - 1)) == row_adjusted_count)
            --rotations_required; // count is a power of 2
        for (int rotation_i = 0; rotation_i < rotations_required; ++rotation_i)
        {
            seal::Ciphertext rotated;
            evaluator()->rotate_rows(retval, (1 << rotation_i), m_galois_keys, rotated, seal::MemoryPoolHandle::ThreadLocal());
            evaluator()->add_inplace(retval, rotated);
        }
        if (count > BFVEncoder()->slot_count() / 2)
        {
            seal::Ciphertext row2 = retval;
            evaluator()->rotate_columns_inplace(row2, m_galois_keys);
            evaluator()->add_inplace(retval, row2);
        }
    }
    else
    {
        encryptor()->encrypt_zero(retval, seal::MemoryPoolHandle::ThreadLocal());
        retval.scale() = cipher.scale();
    }

    return retval;
}

seal::Ciphertext SEALContextWrapper::accumulateCKKS(const seal::Ciphertext &cipher, std::size_t count)
{
    assert(CKKSEncoder());
    if (count > CKKSEncoder()->slot_count())
        count = CKKSEncoder()->slot_count();

    seal::Ciphertext retval;
    if (count > 0)
    {
        retval                  = cipher;
        auto rotations_required = seal::util::get_significant_bit_count(count); // ceil(log2(CKKSEncoder()->slot_count()));
        if (static_cast<decltype(count)>(1 << (rotations_required - 1)) == count)
            --rotations_required; // count is a power of 2
        for (int rotation_i = 0; rotation_i < rotations_required; ++rotation_i)
        {
            seal::Ciphertext rotated;
            evaluator()->rotate_vector(retval, (1 << rotation_i), m_galois_keys, rotated, seal::MemoryPoolHandle::ThreadLocal());
            evaluator()->add_inplace(retval, rotated);
        }
    }
    else
    {
        encryptor()->encrypt_zero(retval, seal::MemoryPoolHandle::ThreadLocal());
    }

    return retval;
}

seal::Ciphertext SEALContextWrapper::collapseCKKS(const std::vector<seal::Ciphertext> &ciphers, bool do_rotate)
{
    // Rotates each cipher to the right by its position in the vector, then
    // multiplies it by an identity with all zeroes and a 1 on the same position
    // as cipher. All these results are added together into a single ciphertext
    // containing only the first element of each ciphertext in ciphers.

    assert(CKKSEncoder());

    seal::Ciphertext retval;
    // initialize the result for addition
    encryptor()->encrypt_zero(retval);
    retval.scale() = scale();
    std::mutex mtx;
    std::exception_ptr p_ex;
#pragma omp parallel for
    for (std::size_t i = 0; i < ciphers.size(); ++i)
    {
        try
        {
            if (!p_ex)
            {
                seal::Ciphertext tmp;
                if (do_rotate && i > 0)
                    evaluator()->rotate_vector(ciphers[i], -static_cast<int>(i), galoisKeys(), tmp, seal::MemoryPoolHandle::ThreadLocal());
                else
                    tmp = ciphers[i];

                std::vector<double> identity(ciphers.size(), 0.0);
                identity[i] = 1.0;
                seal::Plaintext plain;
                CKKSEncoder()->encode(identity, scale(), plain);

                // multiply cipher by identity
                evaluator()->mod_switch_to_inplace(plain, tmp.parms_id()); // put plain to the same level as cipher
                evaluator()->multiply_plain_inplace(tmp, plain, seal::MemoryPoolHandle::ThreadLocal());
                evaluator()->relinearize_inplace(tmp, relinKeys(), seal::MemoryPoolHandle::ThreadLocal());
                evaluator()->rescale_to_next_inplace(tmp, seal::MemoryPoolHandle::ThreadLocal());

                // add the result to output cipher

                tmp.scale() = scale(); // results will be incorrect if scales are not close enough

                std::scoped_lock<std::mutex> lock(mtx);
                matchLevel(retval, tmp); // make sure both ciphers are at the same level in the modulus switching chain
                retval.scale() = tmp.scale(); // match scales (results are incorrect if scales are not close enough)
                evaluator()->add_inplace(retval, tmp);
            } // end if
        }
        catch (...)
        {
            std::scoped_lock<std::mutex> lock(mtx);
            if (!p_ex)
                p_ex = std::current_exception();
        }
    } // end for

    if (p_ex)
        std::rethrow_exception(p_ex);

    return retval;
}

seal::Ciphertext SEALContextWrapper::evaluatePolynomial(seal::Ciphertext &cipher_input,
                                                        std::vector<seal::Plaintext> &plain_coefficients)
{
    if (plain_coefficients.empty())
    {
        throw hebench::cpp::HEBenchError(HEBERROR_MSG_CLASS("Polynomial must have, at least, 1 coefficient."),
                                         HEBENCH_ECODE_INVALID_ARGS);
    } // end if

    // Each coefficient is encoded per plaintext (it is assumed that every slot in the
    // plaintext contains the same coefficient value.
    // This method requires, at least plain_coefficients.size() - 1 coefficient
    // moduli left in the chain.

    // perform evaluation using Horner's method:
    // f(x) = a_n * x^n + a_n-1 * x^(n-1) +... + a_1 * x + a_0
    //      = (...(((a_n * x + a_n-1) * x + a_n-2) * x ... + a_1) * x + a_0
    //
    // Adapted from:
    // https://github.com/MarwanNour/SEAL-FYP-Logistic-Regression/blob/master/logistic_regression_ckks.cpp
    seal::Ciphertext retval;

    auto it = plain_coefficients.rbegin();
    encryptor()->encrypt(*it, retval);
    for (++it; it != plain_coefficients.rend(); ++it)
    {
        // make sure both items to multiply are at the same level
        matchLevel(cipher_input, retval);
        // multiply current result by input
        evaluator()->multiply_inplace(retval, cipher_input);
        evaluator()->relinearize_inplace(retval, relinKeys());
        evaluator()->rescale_to_next_inplace(retval);

        // prepare sum
        evaluator()->mod_switch_to_inplace(*it, retval.parms_id());
        retval.scale() = it->scale(); // manual scaling (results will be wrong if scales are not close enough)
        // add current result to next coefficient
        evaluator()->add_plain_inplace(retval, *it);
    } // end for

    return retval;
}
