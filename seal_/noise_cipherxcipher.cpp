#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <fstream>

using namespace std;
using namespace seal;

void experiment_ct_x_ct_for_degree(size_t poly_modulus_degree) {
    ofstream output_file("ct_x_ct_results_" + to_string(poly_modulus_degree) + ".txt", ios::app);
    
    // Set up encryption parameters for specific degree
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    
    // Use appropriate coefficient modulus for each degree
    vector<int> bit_sizes;
    if (poly_modulus_degree == 1024) {
        bit_sizes = {27, 27, 27};  // Smaller for 1024
    } else if (poly_modulus_degree == 2048) {
        bit_sizes = {54, 54, 55};
    } else if (poly_modulus_degree == 4096) {
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    } else if (poly_modulus_degree == 8192) {
        bit_sizes = {54, 54, 54, 54, 55};
    } else if (poly_modulus_degree == 16384) {
        bit_sizes = {54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 54, 55};
    } else if (poly_modulus_degree == 32768) {
        bit_sizes = {60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60, 60};
    }
    
    if (!bit_sizes.empty()) {
        parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
    } else {
        parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    }
    
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));
    
    SEALContext context(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    
    cout << "=== Ciphertext × Ciphertext Operations (Poly Degree: " << poly_modulus_degree << ") ===" << endl;
    cout << "Operations\tNoise Budget" << endl;
    cout << "----------------------------------------" << endl;
    
    output_file << "=== Ciphertext × Ciphertext Operations (Poly Degree: " << poly_modulus_degree << ") ===" << endl;
    output_file << "Operations\tNoise Budget" << endl;
    output_file << "----------------------------------------" << endl;
    
    // Initialize with two ciphertexts
    Plaintext plain1("1"), plain2("2");
    Ciphertext ct1, ct2, result;
    encryptor.encrypt(plain1, ct1);
    encryptor.encrypt(plain2, ct2);
    
    // Start with multiplication
    evaluator.multiply(ct1, ct2, result);
    evaluator.relinearize_inplace(result, relin_keys);
    
    int operation_count = 1;
    int noise_budget = decryptor.invariant_noise_budget(result);
    cout << operation_count << "\t\t" << noise_budget << endl;
    output_file << operation_count << "\t\t" << noise_budget << endl;
    
    // Perform operations in powers of 2
    vector<int> operation_sequence;
    if (poly_modulus_degree <= 4096) {
        operation_sequence = {2, 4, 8, 16, 32, 64, 128};
    } else {
        operation_sequence = {2, 4, 8, 16, 32};
    }
    
    for (int target_ops : operation_sequence) {
        while (operation_count < target_ops) {
            evaluator.multiply_inplace(result, ct2);
            evaluator.relinearize_inplace(result, relin_keys);
            operation_count++;
            
            // Check if we can still decrypt
            noise_budget = decryptor.invariant_noise_budget(result);
            if (noise_budget <= 0) {
                cout << operation_count << "\t\t" << "NOISE EXHAUSTED" << endl;
                output_file << operation_count << "\t\t" << "NOISE EXHAUSTED" << endl;
                output_file.close();
                return;
            }
        }
        noise_budget = decryptor.invariant_noise_budget(result);
        cout << operation_count << "\t\t" << noise_budget << endl;
        output_file << operation_count << "\t\t" << noise_budget << endl;
    }
    
    output_file.close();
}

void experiment_ct_x_ct() {
    vector<size_t> poly_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
    
    for (size_t degree : poly_degrees) {
        try {
            experiment_ct_x_ct_for_degree(degree);
            cout << endl;
        } catch (const exception &e) {
            cout << "Failed for degree " << degree << ": " << e.what() << endl;
        }
    }
}

int main() {
    try {
        cout << "EXPERIMENT 5: Ciphertext × Ciphertext Multiplication (All Poly Degrees)" << endl;
        cout << "=======================================================================" << endl << endl;
        
        experiment_ct_x_ct();
        
        cout << endl << "Results saved to separate files for each polynomial degree." << endl;
        
    } catch (const exception &e) {
        cerr << "Error: " << e.what() << endl;
        return -1;
    }
    
    return 0;
}
