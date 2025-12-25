#include <iostream>
#include <vector>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include "seal/seal.h"

using namespace std;
using namespace seal;

class CipherTimesCipherExperiment {
private:
    vector<int> poly_modulus_degrees = {1024, 2048, 4096, 8192, 16384};

    uint64_t get_plaintext_modulus(int poly_degree) {
        // Use smaller primes that work with smaller polynomial degrees
        switch(poly_degree) {
            case 1024: return 40961;    // Smaller prime that works with 1024
            case 2048: return 40961;    // Same for 2048
            case 4096: return 65537;
            case 8192: return 65537;
            case 16384: return 65537;
            default: return 65537;
        }
    }

    shared_ptr<SEALContext> generate_context(int poly_degree) {
        EncryptionParameters parms(scheme_type::bfv);
        parms.set_poly_modulus_degree(poly_degree);
        
        // For small degrees, we need to be more careful with parameter selection
        if (poly_degree == 1024) {
            // Use a simpler approach - let SEAL choose compatible parameters
            parms.set_plain_modulus(PlainModulus::Batching(poly_degree, 20));
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree));
        }
        else if (poly_degree == 2048) {
            parms.set_plain_modulus(PlainModulus::Batching(poly_degree, 20));
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree));
        }
        else if (poly_degree == 4096) {
            parms.set_plain_modulus(get_plaintext_modulus(poly_degree));
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree));
        }
        else {
            parms.set_plain_modulus(get_plaintext_modulus(poly_degree));
            parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_degree));
        }
        
        return make_shared<SEALContext>(parms);
    }

    string get_coeff_modulus_string(shared_ptr<SEALContext> context) {
        auto context_data = context->first_context_data();
        stringstream ss;
        ss << "[";
        while (context_data) {
            ss << context_data->parms().coeff_modulus()[0].bit_count();
            context_data = context_data->next_context_data();
            if (context_data) ss << " ";
        }
        ss << "]";
        return ss.str();
    }

    int test_cipher_times_cipher_operations(shared_ptr<SEALContext> context, 
                                           const vector<uint64_t>& initial_vec) {
        // Verify context supports the operations we need
        if (!context->parameters_set()) {
            cout << "      Context parameters not valid!" << endl;
            return 0;
        }
        
        auto context_data = context->first_context_data();
        if (!context_data->qualifiers().using_batching) {
            cout << "      Context doesn't support batching!" << endl;
            return 0;
        }

        try {
            KeyGenerator keygen(*context);
            PublicKey public_key;
            keygen.create_public_key(public_key);
            SecretKey secret_key = keygen.secret_key();
            RelinKeys relin_keys;
            keygen.create_relin_keys(relin_keys);
            
            Encryptor encryptor(*context, public_key);
            Evaluator evaluator(*context);
            Decryptor decryptor(*context, secret_key);
            BatchEncoder batch_encoder(*context);
            
            // Encode and encrypt initial vectors
            Plaintext plain1, plain2;
            batch_encoder.encode(initial_vec, plain1);
            batch_encoder.encode(initial_vec, plain2);
            
            Ciphertext cipher1, cipher2;
            encryptor.encrypt(plain1, cipher1);
            encryptor.encrypt(plain2, cipher2);
            
            int operation_count = 0;
            uint64_t t = context->first_context_data()->parms().plain_modulus().value();
            
            while (operation_count < 16384) {
                evaluator.multiply_inplace(cipher1, cipher2);
                evaluator.relinearize_inplace(cipher1, relin_keys);
                operation_count++;
                
                // Verify result
                Plaintext result_plain;
                decryptor.decrypt(cipher1, result_plain);
                vector<uint64_t> result_vec;
                batch_encoder.decode(result_plain, result_vec);
                
                // Check if results match expected
                bool matches = true;
                for (size_t i = 0; i < initial_vec.size(); i++) {
                    uint64_t expected = 1;
                    for (int j = 0; j < operation_count + 1; j++) {
                        expected = (expected * initial_vec[i]) % t;
                    }
                    if (result_vec[i] != expected) {
                        matches = false;
                        break;
                    }
                }
                
                if (!matches) {
                    cout << "      Result mismatch after " << operation_count << " operations" << endl;
                    break;
                }
            }
            
            if (operation_count >= 16384) {
                cout << "      Hit safety cap at " << operation_count << " operations" << endl;
            }
            
            return operation_count;
            
        } catch (const exception& e) {
            cout << "      Operation failed: " << e.what() << endl;
            return 0;
        }
    }

public:
    void run_experiment() {
        cout << "Starting Experiment: Cipher_Times_Cipher_Experiment" << endl;
        cout << "Testing MAXIMUM CIPHERTEXT × CIPHERTEXT OPERATIONS" << endl;
        cout << "Using SEAL DEFAULT PARAMETERS WITH BATCHING" << endl;
        cout << string(80, '=') << endl;
        
        ofstream output_file("cipher_times_cipher_results.csv");
        output_file << "poly_degree,modulus_chain,max_operations,plaintext_modulus,operation_type" << endl;
        
        for (int poly_degree : poly_modulus_degrees) {
            cout << "\nTesting with polynomial modulus degree: " << poly_degree << endl;
            
            try {
                auto context = generate_context(poly_degree);
                
                if (!context->parameters_set()) {
                    cout << "  ERROR: Context parameters not valid for degree " << poly_degree << endl;
                    continue;
                }
                
                string coeff_modulus_str = get_coeff_modulus_string(context);
                cout << "  Coefficient modulus: " << coeff_modulus_str << endl;
                cout << "  Plaintext modulus: " << context->first_context_data()->parms().plain_modulus().value() << endl;
                
                vector<uint64_t> initial_vec(16, 2);
                int max_operations = test_cipher_times_cipher_operations(context, initial_vec);
                
                output_file << poly_degree << ",\"" << coeff_modulus_str << "\"," 
                           << max_operations << "," << context->first_context_data()->parms().plain_modulus().value() 
                           << ",cipher_times_cipher" << endl;
                
                cout << "  Maximum CT×CT operations: " << max_operations << endl;
                
            } catch (const exception& e) {
                cout << "  ERROR: " << e.what() << endl;
            }
        }
        
        output_file.close();
        cout << "\nResults saved to: cipher_times_cipher_results.csv" << endl;
    }
};

int main() {
    CipherTimesCipherExperiment experiment;
    experiment.run_experiment();
    cout << "Cipher × Cipher Experiment completed!" << endl;
    return 0;
}
