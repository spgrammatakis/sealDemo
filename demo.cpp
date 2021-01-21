 // Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.
#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
    print_example_banner("Example: CKKS Basics");
    
    EncryptionParameters parms(scheme_type::ckks);

    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    double scale = pow(2.0, 40);

    SEALContext context(parms);
    print_parameters(context);
    cout << endl;

    KeyGenerator keygen(context);
    auto secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    keygen.create_galois_keys(gal_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);

    CKKSEncoder encoder(context);
    size_t slot_count = encoder.slot_count();
    cout << "Number of slots: " << slot_count << endl;

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++)
    {
        input.push_back(curr_point);
        curr_point += step_size;
    }
    cout << "Input vector: " << endl;
    print_vector(input, 3, 7);

    cout << "Evaluating polynomial 5*x^2 + 3.2x + 2.0 ..." << endl;

    Plaintext plain_coeff2, plain_coeff1, plain_coeff0;
    encoder.encode(5.0, scale, plain_coeff2);
    encoder.encode(3.2, scale, plain_coeff1);
    encoder.encode(2.0, scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);

    Ciphertext x2_encrypted;
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x2_encrypted);
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;
    
    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    evaluator.rescale_to_next_inplace(x2_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;
    
    print_line(__LINE__);
    cout << "Compute and rescale 5*x." << endl;
    Ciphertext x1_encrypted_coeff2;
    evaluator.multiply_plain(x1_encrypted, plain_coeff2, x1_encrypted_coeff2);
    cout << "    + Scale of 5*x before rescale: " << log2(x1_encrypted_coeff2.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff2);
    cout << "    + Scale of 5*x after rescale: " << log2(x1_encrypted_coeff2.scale()) << " bits" << endl;

 // Giati x^3?
    print_line(__LINE__);
    cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
    evaluator.multiply_inplace(x2_encrypted, x1_encrypted_coeff2);
    evaluator.relinearize_inplace(x2_encrypted, relin_keys);
    cout << "    + Scale of PI*x^3 before rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x2_encrypted);
    cout << "    + Scale of PI*x^3 after rescale: " << log2(x2_encrypted.scale()) << " bits" << endl;
    
    print_line(__LINE__);
    cout << "Compute and rescale 0.4*x." << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "    + Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale()) << " bits" << endl;

    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x2_encrypted: "
         << context.get_context_data(x2_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
         << context.get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for plain_coeff0: "
         << context.get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;


    print_line(__LINE__);
    cout << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "    + Exact scale in 5*x^2: " << x2_encrypted.scale() << endl;
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

   
    print_line(__LINE__);
    cout << "Normalize scales to 2^40." << endl;
    x2_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

   
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl;
    parms_id_type last_parms_id = x2_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    print_line(__LINE__);
    cout << "tCompute 5.0*x^2 + 3.2*x + 2.0." << endl;
    Ciphertext encrypted_result;
    evaluator.add(x2_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode 5.0*x^2 + 3.2x + 2.0." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((5.0 * x + 3.2) * x + 2.0);
    }
    print_vector(true_result, 3, 7);

    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);

}
