#include <seal/seal.h>
#include <vector>
#include <iostream>
#include <fstream>
#include <chrono>
#include <cmath>

using namespace std;
using namespace seal;

class SEALExperimentSameInteger {
private:
    shared_ptr<SEALContext> context;
    KeyGenerator *keygen;
    SecretKey secret_key;
    PublicKey public_key;
    Encryptor *encryptor;
    Evaluator *evaluator;
    Decryptor *decryptor;
    BatchEncoder *batch_encoder;
    
    ofstream log_file;

public:
    SEALExperimentSameInteger() : keygen(nullptr), encryptor(nullptr), evaluator(nullptr), 
                                  decryptor(nullptr), batch_encoder(nullptr) {
        log_file.open("seal_experiment_same_integer.csv");
        log_file << "poly_modulus_degree,vector_size,operation_type,encryption_time_ms,operation_time_ms,decryption_time_ms\n";
    }

    ~SEALExperimentSameInteger() {
        cleanup();
        if (log_file.is_open()) {
            log_file.close();
        }
    }

    void cleanup() {
        if (batch_encoder) delete batch_encoder;
        if (decryptor) delete decryptor;
        if (evaluator) delete evaluator;
        if (encryptor) delete encryptor;
        if (keygen) delete keygen;
    }

    bool try_parameters(size_t poly_modulus_degree, const vector<int>& bit_sizes, uint64_t plain_mod) {
        try {
            EncryptionParameters params(scheme_type::bfv);
            params.set_poly_modulus_degree(poly_modulus_degree);
            params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, bit_sizes));
            params.set_plain_modulus(plain_mod);
            
            context = make_shared<SEALContext>(params);
            
            if (!context->parameters_set()) {
                return false;
            }
            
            // Test if we can create all the necessary objects
            keygen = new KeyGenerator(*context);
            secret_key = keygen->secret_key();
            keygen->create_public_key(public_key);
            encryptor = new Encryptor(*context, public_key);
            evaluator = new Evaluator(*context);
            decryptor = new Decryptor(*context, secret_key);
            batch_encoder = new BatchEncoder(*context);
            
            return true;
        } catch (const exception& e) {
            cleanup();
            return false;
        }
    }

    bool setup_context(size_t poly_modulus_degree) {
        cleanup();

        cout << "Setting up context for poly_modulus_degree: " << poly_modulus_degree << endl;

        // Try different parameter combinations
        vector<vector<int>> coeff_modulus_options;
        vector<uint64_t> plain_modulus_options = {65537, 12289, 40961, 114689};
        
        if (poly_modulus_degree == 1024) {
            coeff_modulus_options = {
                {27, 27},      // 2 moduli
                {30, 30},      // 2 moduli  
                {27, 27, 27},  // 3 moduli
                {20, 20}       // Smaller moduli
            };
        } else if (poly_modulus_degree == 2048) {
            coeff_modulus_options = {
                {36, 36, 37},  // 3 moduli
                {30, 30, 30},  // 3 smaller moduli
                {36, 36},      // 2 moduli
                {27, 27, 27}   // 3 smaller moduli
            };
        } else if (poly_modulus_degree == 4096) {
            coeff_modulus_options = {
                {36, 36, 37},
                {43, 43, 44},
                {36, 36}
            };
        } else if (poly_modulus_degree == 8192) {
            coeff_modulus_options = {
                {43, 43, 44, 44},
                {50, 50, 50, 50}
            };
        } else if (poly_modulus_degree == 16384) {
            coeff_modulus_options = {
                {43, 43, 44, 44},
                {50, 50, 50, 50}
            };
        } else if (poly_modulus_degree == 32768) {
            coeff_modulus_options = {
                {50, 50, 50, 50, 50},
                {60, 60, 60, 60, 60}
            };
        }

        // Try all combinations
        for (const auto& coeff_modulus : coeff_modulus_options) {
            for (auto plain_mod : plain_modulus_options) {
                cout << "  Trying coeff_modulus: [";
                for (size_t i = 0; i < coeff_modulus.size(); i++) {
                    cout << coeff_modulus[i];
                    if (i < coeff_modulus.size() - 1) cout << ", ";
                }
                cout << "], plain_modulus: " << plain_mod << " ... ";
                
                if (try_parameters(poly_modulus_degree, coeff_modulus, plain_mod)) {
                    cout << "SUCCESS!" << endl;
                    cout << "  Context setup completed successfully" << endl;
                    cout << "  Slot count: " << batch_encoder->slot_count() << endl;
                    return true;
                } else {
                    cout << "FAILED" << endl;
                    cleanup();
                }
            }
        }

        // If all else fails, try with batching
        cout << "  Trying with batching plain modulus..." << endl;
        try {
            EncryptionParameters params(scheme_type::bfv);
            params.set_poly_modulus_degree(poly_modulus_degree);
            
            // Use conservative parameters
            if (poly_modulus_degree == 1024) {
                params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {20, 20}));
            } else if (poly_modulus_degree == 2048) {
                params.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, {27, 27, 27}));
            } else {
                params.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
            }
            
            params.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 16)); // Smaller bit size
            
            context = make_shared<SEALContext>(params);
            
            if (context->parameters_set()) {
                keygen = new KeyGenerator(*context);
                secret_key = keygen->secret_key();
                keygen->create_public_key(public_key);
                encryptor = new Encryptor(*context, public_key);
                evaluator = new Evaluator(*context);
                decryptor = new Decryptor(*context, secret_key);
                batch_encoder = new BatchEncoder(*context);
                
                cout << "  SUCCESS with batching!" << endl;
                cout << "  Context setup completed successfully" << endl;
                cout << "  Slot count: " << batch_encoder->slot_count() << endl;
                return true;
            }
        } catch (const exception& e) {
            cout << "  Batching also failed: " << e.what() << endl;
        }

        cout << "  ERROR: No working parameters found for poly_modulus_degree: " << poly_modulus_degree << endl;
        return false;
    }

    void log_operation(size_t poly_modulus_degree, size_t vector_size, const string& operation_type,
                       double encryption_time, double operation_time, double decryption_time) {
        log_file << poly_modulus_degree << "," << vector_size << "," << operation_type << ","
                 << encryption_time << "," << operation_time << "," << decryption_time << endl;
        
        cout << "PolyModulus: " << poly_modulus_degree 
             << ", VectorSize: " << vector_size
             << ", Operation: " << operation_type
             << ", Encrypt: " << encryption_time << " ms"
             << ", Operation: " << operation_time << " ms"
             << ", Decrypt: " << decryption_time << " ms" << endl;
    }

    void test_operation_single(size_t poly_modulus_degree, size_t vector_size, const string& operation_type) {
        size_t slot_count = batch_encoder->slot_count();
        
        // Prepare data - same integer in all slots
        int same_value = 42;
        vector<uint64_t> plain_vector(slot_count, same_value);
        Plaintext plain;
        batch_encoder->encode(plain_vector, plain);

        // Encryption time
        auto start_encrypt = chrono::high_resolution_clock::now();
        Ciphertext cipher;
        encryptor->encrypt(plain, cipher);
        auto end_encrypt = chrono::high_resolution_clock::now();
        double encrypt_time = chrono::duration<double, milli>(end_encrypt - start_encrypt).count();

        // Operation time
        auto start_op = chrono::high_resolution_clock::now();
        Ciphertext result;
        
        if (operation_type == "CIPHER_ADD_CIPHER") {
            evaluator->add(cipher, cipher, result);
        }
        else if (operation_type == "CIPHER_ADD_PLAIN") {
            evaluator->add_plain(cipher, plain, result);
        }
        else if (operation_type == "CIPHER_MUL_PLAIN") {
            evaluator->multiply_plain(cipher, plain, result);
        }
        else if (operation_type == "CIPHER_MUL_CIPHER") {
            evaluator->multiply(cipher, cipher, result);
        }
        
        auto end_op = chrono::high_resolution_clock::now();
        double operation_time = chrono::duration<double, milli>(end_op - start_op).count();

        // Decryption time
        Plaintext decrypted;
        auto start_decrypt = chrono::high_resolution_clock::now();
        decryptor->decrypt(result, decrypted);
        auto end_decrypt = chrono::high_resolution_clock::now();
        double decrypt_time = chrono::duration<double, milli>(end_decrypt - start_decrypt).count();

        log_operation(poly_modulus_degree, vector_size, operation_type, encrypt_time, operation_time, decrypt_time);
    }

    void test_operation_large_vector(size_t poly_modulus_degree, size_t vector_size, const string& operation_type) {
        size_t slot_count = batch_encoder->slot_count();
        size_t num_ciphertexts = (vector_size + slot_count - 1) / slot_count;

        double total_encrypt_time = 0;
        double total_operation_time = 0;
        double total_decrypt_time = 0;

        // Prepare data - same integer in all slots
        int same_value = 42;
        vector<uint64_t> plain_vector(slot_count, same_value);
        Plaintext plain;
        batch_encoder->encode(plain_vector, plain);

        for (size_t i = 0; i < num_ciphertexts; i++) {
            // Encryption
            auto start_encrypt = chrono::high_resolution_clock::now();
            Ciphertext cipher;
            encryptor->encrypt(plain, cipher);
            auto end_encrypt = chrono::high_resolution_clock::now();
            total_encrypt_time += chrono::duration<double, milli>(end_encrypt - start_encrypt).count();

            // Operation
            auto start_op = chrono::high_resolution_clock::now();
            Ciphertext result;
            
            if (operation_type == "CIPHER_ADD_CIPHER") {
                evaluator->add(cipher, cipher, result);
            }
            else if (operation_type == "CIPHER_ADD_PLAIN") {
                evaluator->add_plain(cipher, plain, result);
            }
            else if (operation_type == "CIPHER_MUL_PLAIN") {
                evaluator->multiply_plain(cipher, plain, result);
            }
            else if (operation_type == "CIPHER_MUL_CIPHER") {
                evaluator->multiply(cipher, cipher, result);
            }
            
            auto end_op = chrono::high_resolution_clock::now();
            total_operation_time += chrono::duration<double, milli>(end_op - start_op).count();

            // Decryption
            Plaintext decrypted;
            auto start_decrypt = chrono::high_resolution_clock::now();
            decryptor->decrypt(result, decrypted);
            auto end_decrypt = chrono::high_resolution_clock::now();
            total_decrypt_time += chrono::duration<double, milli>(end_decrypt - start_decrypt).count();
        }

        // Average times per ciphertext
        log_operation(poly_modulus_degree, vector_size, operation_type,
                     total_encrypt_time / num_ciphertexts,
                     total_operation_time / num_ciphertexts,
                     total_decrypt_time / num_ciphertexts);
    }

    void run_experiment(size_t poly_modulus_degree, size_t vector_size) {
        cout << "\n=== Starting Experiment: PolyModulus=" << poly_modulus_degree 
             << ", VectorSize=" << vector_size << " ===" << endl;
        
        if (!setup_context(poly_modulus_degree)) {
            cout << "SKIPPING - Failed to setup context for poly_modulus_degree: " << poly_modulus_degree << endl;
            return;
        }
        
        size_t slot_count = batch_encoder->slot_count();
        
        cout << "Testing - PolyModulus: " << poly_modulus_degree 
             << ", VectorSize: " << vector_size 
             << ", SlotCount: " << slot_count 
             << ", CiphertextsNeeded: " << ((vector_size + slot_count - 1) / slot_count) << endl;

        // Test each operation separately
        vector<string> operations = {
            "CIPHER_ADD_CIPHER",
            "CIPHER_ADD_PLAIN", 
            "CIPHER_MUL_PLAIN",
            "CIPHER_MUL_CIPHER"
        };

        for (const auto& operation : operations) {
            cout << "  Testing operation: " << operation << endl;
            if (vector_size <= slot_count) {
                // Single ciphertext case
                test_operation_single(poly_modulus_degree, vector_size, operation);
            } else {
                // Multiple ciphertexts case
                test_operation_large_vector(poly_modulus_degree, vector_size, operation);
            }
        }
        
        cout << "=== Completed Experiment: PolyModulus=" << poly_modulus_degree 
             << ", VectorSize=" << vector_size << " ===" << endl;
    }

    void run_all_experiments() {
        vector<size_t> poly_modulus_degrees = {1024, 2048, 4096, 8192, 16384, 32768};
        vector<size_t> vector_sizes;
        
        // Generate vector sizes from 2^10 to 2^20
        for (int i = 10; i <= 20; i++) {
            vector_sizes.push_back(1 << i);
        }

        for (auto poly_degree : poly_modulus_degrees) {
            for (auto vec_size : vector_sizes) {
                run_experiment(poly_degree, vec_size);
            }
        }
    }
};

int main() {
    SEALExperimentSameInteger experiment;
    cout << "Starting Same Integer Experiments..." << endl;
    experiment.run_all_experiments();
    cout << "Same Integer Experiments Completed!" << endl;
    return 0;
}
